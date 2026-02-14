//go:build stress

package stress

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"storas/internal/api"
	"storas/internal/authz"
	"storas/internal/sigv4"
	"storas/internal/storage"
)

const (
	stressAccessKey = "AKIAFULL"
	stressSecretKey = "secret-full"
)

func newStressServer(t *testing.T, maxBodyBytes int64) (*httptest.Server, func()) {
	t.Helper()
	dir := t.TempDir()
	backend, err := storage.NewFSBackend(filepath.Join(dir, "data"), 25*1024*1024*1024)
	if err != nil {
		t.Fatalf("NewFSBackend: %v", err)
	}
	authPath := filepath.Join(dir, "authorization.yaml")
	authYAML := `users:
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
`
	if err := os.WriteFile(authPath, []byte(authYAML), 0o600); err != nil {
		t.Fatalf("write auth yaml: %v", err)
	}
	engine, err := authz.LoadFile(authPath)
	if err != nil {
		t.Fatalf("LoadFile authz: %v", err)
	}
	svc := &api.Service{
		Backend:      backend,
		Authz:        engine,
		Region:       "us-west-1",
		ServiceName:  "s3",
		ClockSkew:    15 * time.Minute,
		Now:          time.Now,
		ServiceHost:  "127.0.0.1",
		MaxBodyBytes: maxBodyBytes,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	server := httptest.NewServer(svc.Handler())
	cleanup := func() { server.Close() }
	return server, cleanup
}

func signedRequest(t *testing.T, now time.Time, method, rawURL string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	date := now.UTC().Format(sigv4.DateFormat)
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonical, err := sigv4.BuildCanonicalRequest(req, signedHeaders, "UNSIGNED-PAYLOAD")
	if err != nil {
		t.Fatalf("BuildCanonicalRequest: %v", err)
	}
	scope := sigv4.CredentialScope{
		AccessKey: stressAccessKey,
		Date:      now.UTC().Format("20060102"),
		Region:    "us-west-1",
		Service:   "s3",
		Terminal:  "aws4_request",
	}
	stringToSign := sigv4.BuildStringToSign(canonical, now.UTC(), scope)
	sig := sigv4.SignatureHex(sigv4.SigningKey(stressSecretKey, scope.Date, scope.Region, scope.Service), stringToSign)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/%s, SignedHeaders=%s, Signature=%s", scope.AccessKey, scope.Date, scope.Region, scope.Service, scope.Terminal, strings.Join(signedHeaders, ";"), sig))
	return req
}

func doSigned(t *testing.T, client *http.Client, now time.Time, method, rawURL string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	req := signedRequest(t, now, method, rawURL, body)
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do %s %s: %v", method, rawURL, err)
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll response %s %s: %v", method, rawURL, err)
	}
	return res, bytes
}

func runWorkers(t *testing.T, workers int, seed int64, fn func(worker int, rng *rand.Rand) error) {
	t.Helper()
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(id)))
			<-start
			errCh <- fn(id, rng)
		}(worker)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
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
