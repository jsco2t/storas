//go:build stress

package stress

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

type createMultipartResult struct {
	UploadID string `xml:"UploadId"`
}

type listMultipartUploadsResult struct {
	Uploads []struct {
		Key      string `xml:"Key"`
		UploadID string `xml:"UploadId"`
	} `xml:"Upload"`
}

func TestStressIntegrationMixedOperationsAndInvariants(t *testing.T) {
	t.Parallel()
	server, cleanup := newStressServer(t, 25*1024*1024)
	defer cleanup()
	client := server.Client()
	now := time.Now().UTC()

	base := server.URL
	bucketURL := base + "/stress-int"
	res, body := doSigned(t, client, now, http.MethodPut, bucketURL, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create bucket failed: status=%d body=%s", res.StatusCode, body)
	}
	if res, body := doSigned(t, client, now, http.MethodPut, bucketURL+"/seed.txt", bytes.NewBufferString("seed")); res.StatusCode != http.StatusOK {
		t.Fatalf("seed put failed: status=%d body=%s", res.StatusCode, body)
	}
	workloadDuration := parseStressWorkloadDuration(t)
	workloadDeadline := time.Now().Add(workloadDuration)

	runWorkers(t, 10, 9000, func(worker int, rng *rand.Rand) error {
		for i := 0; ; i++ {
			if workloadDuration > 0 {
				if time.Now().After(workloadDeadline) {
					break
				}
			} else if i >= 50 {
				break
			}
			key := fmt.Sprintf("obj-%02d.txt", rng.Intn(10))
			switch rng.Intn(8) {
			case 0:
				res, body := doSigned(t, client, now, http.MethodPut, bucketURL+"/"+key, bytes.NewBufferString(fmt.Sprintf("w=%d i=%d", worker, i)))
				if res.StatusCode != http.StatusOK {
					return fmt.Errorf("put failed status=%d body=%s", res.StatusCode, body)
				}
			case 1:
				res, body := doSigned(t, client, now, http.MethodGet, bucketURL+"/"+key, nil)
				if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotFound {
					return fmt.Errorf("get failed status=%d body=%s", res.StatusCode, body)
				}
			case 2:
				res, body := doSigned(t, client, now, http.MethodHead, bucketURL+"/"+key, nil)
				if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotFound {
					return fmt.Errorf("head failed status=%d body=%s", res.StatusCode, body)
				}
			case 3:
				res, body := doSigned(t, client, now, http.MethodDelete, bucketURL+"/"+key, nil)
				if res.StatusCode != http.StatusNoContent {
					return fmt.Errorf("delete failed status=%d body=%s", res.StatusCode, body)
				}
			case 4:
				req := signedRequest(t, now, http.MethodPut, bucketURL+"/copy-"+key, nil)
				req.Header.Set("X-Amz-Copy-Source", "/stress-int/seed.txt")
				res, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("copy request failed: %w", err)
				}
				body, readErr := io.ReadAll(res.Body)
				_ = res.Body.Close()
				if readErr != nil {
					return fmt.Errorf("copy response read failed: %w", readErr)
				}
				if res.StatusCode != http.StatusOK {
					return fmt.Errorf("copy failed status=%d body=%s", res.StatusCode, body)
				}
			case 5:
				listURL := bucketURL + "?list-type=2&max-keys=3&prefix=obj-"
				res, body := doSigned(t, client, now, http.MethodGet, listURL, nil)
				if res.StatusCode != http.StatusOK {
					return fmt.Errorf("list failed status=%d body=%s", res.StatusCode, body)
				}
			case 6:
				if err := multipartRoundTrip(t, client, now, bucketURL, key); err != nil {
					return err
				}
			default:
				if err := listMultipartUploads(t, client, now, bucketURL); err != nil {
					return err
				}
			}
		}
		return nil
	})

	seen := map[string]struct{}{}
	next := ""
	for {
		listURL := bucketURL + "?list-type=2&max-keys=2"
		if next != "" {
			listURL += "&continuation-token=" + url.QueryEscape(next)
		}
		res, body := doSigned(t, client, now, http.MethodGet, listURL, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("final list failed status=%d body=%s", res.StatusCode, body)
		}
		var parsed listBucketResult
		if err := xml.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("parse list response: %v", err)
		}
		for _, c := range parsed.Contents {
			if _, ok := seen[c.Key]; ok {
				t.Fatalf("duplicate key across list pages: %s", c.Key)
			}
			seen[c.Key] = struct{}{}
			res, body := doSigned(t, client, now, http.MethodHead, bucketURL+"/"+c.Key, nil)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("head existing key %s failed status=%d body=%s", c.Key, res.StatusCode, body)
			}
			getRes, getBody := doSigned(t, client, now, http.MethodGet, bucketURL+"/"+c.Key, nil)
			if getRes.StatusCode != http.StatusOK {
				t.Fatalf("get existing key %s failed status=%d body=%s", c.Key, getRes.StatusCode, getBody)
			}
			if cl := strings.TrimSpace(getRes.Header.Get("Content-Length")); cl != "" && cl != fmt.Sprintf("%d", len(getBody)) {
				t.Fatalf("content-length mismatch for %s: header=%s actual=%d", c.Key, cl, len(getBody))
			}
		}
		if !parsed.IsTruncated {
			break
		}
		next = parsed.NextContinuationToken
		if next == "" {
			t.Fatal("missing continuation token on truncated response")
		}
	}
}

func TestStressIntegrationCancellationAndDisconnect(t *testing.T) {
	t.Parallel()
	server, cleanup := newStressServer(t, 25*1024*1024)
	defer cleanup()
	client := server.Client()
	now := time.Now().UTC()

	base := server.URL
	bucketURL := base + "/stress-cancel"
	if res, body := doSigned(t, client, now, http.MethodPut, bucketURL, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("create bucket failed status=%d body=%s", res.StatusCode, body)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := signedRequest(t, now, http.MethodPut, bucketURL+"/cancelled.bin", io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), 1024*1024))))
	req = req.WithContext(ctx)
	cancel()
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected canceled request error")
	}

	rawURL, parseErr := url.Parse(server.URL)
	if parseErr != nil {
		t.Fatalf("parse server url: %v", parseErr)
	}
	conn, dialErr := net.Dial("tcp", rawURL.Host)
	if dialErr != nil {
		t.Fatalf("dial server: %v", dialErr)
	}
	_, _ = conn.Write([]byte("PUT /stress-cancel/partial.bin HTTP/1.1\r\nHost: " + rawURL.Host + "\r\nContent-Length: 100000\r\n\r\npartial"))
	_ = conn.Close()

	if res, body := doSigned(t, client, now, http.MethodPut, bucketURL+"/healthy.txt", bytes.NewBufferString("ok")); res.StatusCode != http.StatusOK {
		t.Fatalf("server unhealthy after disconnect status=%d body=%s", res.StatusCode, body)
	}
}

func multipartRoundTrip(t *testing.T, client *http.Client, now time.Time, bucketURL, key string) error {
	initURL := bucketURL + "/" + key + "?uploads="
	res, body := doSigned(t, client, now, http.MethodPost, initURL, nil)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("init multipart failed status=%d body=%s", res.StatusCode, body)
	}
	var init createMultipartResult
	if err := xml.Unmarshal(body, &init); err != nil {
		return fmt.Errorf("decode multipart init: %w", err)
	}
	if strings.TrimSpace(init.UploadID) == "" {
		return fmt.Errorf("missing upload id in multipart init")
	}
	part1URL := bucketURL + "/" + key + "?partNumber=1&uploadId=" + url.QueryEscape(init.UploadID)
	if res, body := doSigned(t, client, now, http.MethodPut, part1URL, bytes.NewBufferString("hello ")); res.StatusCode != http.StatusOK {
		return fmt.Errorf("multipart part1 failed status=%d body=%s", res.StatusCode, body)
	}
	part2URL := bucketURL + "/" + key + "?partNumber=2&uploadId=" + url.QueryEscape(init.UploadID)
	if res, body := doSigned(t, client, now, http.MethodPut, part2URL, bytes.NewBufferString("world")); res.StatusCode != http.StatusOK {
		return fmt.Errorf("multipart part2 failed status=%d body=%s", res.StatusCode, body)
	}
	completeBody := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part><Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>`
	completeURL := bucketURL + "/" + key + "?uploadId=" + url.QueryEscape(init.UploadID)
	if res, body := doSigned(t, client, now, http.MethodPost, completeURL, bytes.NewBufferString(completeBody)); res.StatusCode != http.StatusOK {
		return fmt.Errorf("multipart complete failed status=%d body=%s", res.StatusCode, body)
	}
	return nil
}

func listMultipartUploads(t *testing.T, client *http.Client, now time.Time, bucketURL string) error {
	res, body := doSigned(t, client, now, http.MethodGet, bucketURL+"?uploads=", nil)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("list multipart uploads failed status=%d body=%s", res.StatusCode, body)
	}
	var parsed listMultipartUploadsResult
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode multipart listing: %w", err)
	}
	seen := map[string]struct{}{}
	for _, up := range parsed.Uploads {
		id := up.Key + "#" + up.UploadID
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate multipart upload in list response: %s", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
