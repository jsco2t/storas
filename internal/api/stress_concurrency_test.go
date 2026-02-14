//go:build stress

package api

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStressAPIHighContentionMixedWorkload(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:list"
        resource: "*"
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "bucket:delete"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
      - action: "object:delete"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/stress-api", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/stress-api/seed.txt", bytes.NewBufferString("seed"), "AKIAFULL", "secret-full"), http.StatusOK)

	const (
		workers    = 10
		iterations = 60
	)
	workloadDuration := parseStressWorkloadDuration(t)
	workloadDeadline := time.Now().Add(workloadDuration)
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(700 + worker)))
			<-start
			for i := 0; ; i++ {
				if workloadDuration > 0 {
					if time.Now().After(workloadDeadline) {
						break
					}
				} else if i >= iterations {
					break
				}
				key := fmt.Sprintf("obj-%02d.txt", rng.Intn(8))
				switch rng.Intn(6) {
				case 0:
					req := signedReq(t, now, http.MethodPut, "http://localhost/stress-api/"+key, bytes.NewBufferString(fmt.Sprintf("w=%d i=%d", worker, i)), "AKIAFULL", "secret-full")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusOK {
						errCh <- fmt.Errorf("put failed: status=%d body=%s", res.Code, res.Body.String())
						return
					}
				case 1:
					req := signedReq(t, now, http.MethodGet, "http://localhost/stress-api/"+key, nil, "AKIAFULL", "secret-full")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusOK && res.Code != http.StatusNotFound {
						errCh <- fmt.Errorf("get failed: status=%d body=%s", res.Code, res.Body.String())
						return
					}
				case 2:
					req := signedReq(t, now, http.MethodHead, "http://localhost/stress-api/"+key, nil, "AKIAFULL", "secret-full")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusOK && res.Code != http.StatusNotFound {
						errCh <- fmt.Errorf("head failed: status=%d", res.Code)
						return
					}
				case 3:
					req := signedReq(t, now, http.MethodDelete, "http://localhost/stress-api/"+key, nil, "AKIAFULL", "secret-full")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusNoContent {
						errCh <- fmt.Errorf("delete failed: status=%d body=%s", res.Code, res.Body.String())
						return
					}
				case 4:
					req := signedReq(t, now, http.MethodGet, "http://localhost/stress-api?list-type=2&max-keys=3", nil, "AKIAFULL", "secret-full")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusOK {
						errCh <- fmt.Errorf("list failed: status=%d body=%s", res.Code, res.Body.String())
						return
					}
				default:
					req := signedReq(t, now, http.MethodPut, "http://localhost/stress-api/copy-"+key, nil, "AKIAFULL", "secret-full")
					req.Header.Set("X-Amz-Copy-Source", "/stress-api/seed.txt")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusOK {
						errCh <- fmt.Errorf("copy failed: status=%d body=%s", res.Code, res.Body.String())
						return
					}
				}
			}
		}(w)
	}

	close(start)
	wg.Wait()
	close(errCh)
	for runErr := range errCh {
		if runErr != nil {
			t.Fatalf("stress worker failure: %v", runErr)
		}
	}

	t.Run("ListPaginationNoDuplicateKeys", func(t *testing.T) {
		continuation := ""
		seen := map[string]struct{}{}
		for {
			url := "http://localhost/stress-api?list-type=2&max-keys=2"
			if continuation != "" {
				url += "&continuation-token=" + continuation
			}
			res := mustRequest(t, h, signedReq(t, now, http.MethodGet, url, nil, "AKIAFULL", "secret-full"), http.StatusOK)
			var parsed struct {
				XMLName               xml.Name `xml:"ListBucketResult"`
				IsTruncated           bool     `xml:"IsTruncated"`
				NextContinuationToken string   `xml:"NextContinuationToken"`
				Contents              []struct {
					Key string `xml:"Key"`
				} `xml:"Contents"`
			}
			if err := xml.Unmarshal(res.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("unmarshal list page: %v", err)
			}
			for _, c := range parsed.Contents {
				if _, ok := seen[c.Key]; ok {
					t.Fatalf("duplicate key across paginated results: %s", c.Key)
				}
				seen[c.Key] = struct{}{}
			}
			if !parsed.IsTruncated {
				break
			}
			continuation = parsed.NextContinuationToken
			if continuation == "" {
				t.Fatal("expected continuation token when truncated")
			}
		}
	})
}

func parseStressWorkloadDuration(t *testing.T) time.Duration {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("STRESS_WORKLOAD_DURATION"))
	if raw == "" {
		return 0
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		t.Fatalf("invalid STRESS_WORKLOAD_DURATION %q: %v", raw, err)
	}
	if duration <= 0 {
		t.Fatalf("invalid STRESS_WORKLOAD_DURATION %q: must be > 0", raw)
	}
	return duration
}
