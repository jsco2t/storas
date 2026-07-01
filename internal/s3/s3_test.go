package s3

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestParseRequestTargetStyles(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://storage.local/backup-a/file.txt", nil)
	target, err := ParseRequestTarget(r, "")
	if err != nil {
		t.Fatalf("ParseRequestTarget path style error: %v", err)
	}
	if target.Bucket != "backup-a" || target.Key != "file.txt" {
		t.Fatalf("unexpected path style target: %+v", target)
	}

	r = httptest.NewRequest(http.MethodGet, "http://backup-b.storage.local/file2.txt", nil)
	r.Host = "backup-b.storage.local"
	target, err = ParseRequestTarget(r, "storage.local")
	if err != nil {
		t.Fatalf("ParseRequestTarget virtual-hosted error: %v", err)
	}
	if target.Bucket != "backup-b" || target.Key != "file2.txt" {
		t.Fatalf("unexpected virtual-hosted target: %+v", target)
	}
}

func TestParseRequestTargetVirtualHostedCaseInsensitive(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://BACKUP-b.STORAGE.local/file2.txt", nil)
	r.Host = "BACKUP-b.STORAGE.local:9000"
	target, err := ParseRequestTarget(r, "storage.LOCAL")
	if err != nil {
		t.Fatalf("ParseRequestTarget virtual-hosted error: %v", err)
	}
	if target.Bucket != "backup-b" || target.Key != "file2.txt" {
		t.Fatalf("unexpected virtual-hosted target: %+v", target)
	}
}

func TestParseRequestTargetVirtualHostedHostAndServiceHostWithPortAndDot(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://backup-b.storage.local./file2.txt", nil)
	r.Host = "backup-b.storage.local.:9000"
	target, err := ParseRequestTarget(r, "storage.local.:9000")
	if err != nil {
		t.Fatalf("ParseRequestTarget virtual-hosted error: %v", err)
	}
	if target.Bucket != "backup-b" || target.Key != "file2.txt" {
		t.Fatalf("unexpected virtual-hosted target: %+v", target)
	}
}

func TestParseRequestTargetPathStyleIPv6Host(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://[2001:db8::1]:9000/backup-a/file.txt", nil)
	r.Host = "[2001:db8::1]:9000"
	target, err := ParseRequestTarget(r, "storage.local")
	if err != nil {
		t.Fatalf("ParseRequestTarget path style error: %v", err)
	}
	if target.Bucket != "backup-a" || target.Key != "file.txt" {
		t.Fatalf("unexpected path style target: %+v", target)
	}
}

func TestResolveOperation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		method   string
		target   RequestTarget
		query    DispatchQuery
		headers  http.Header
		expected Operation
	}{
		// --- bucket-level operations (target.Key == "") ---
		{"bucket-level list-objects with list-type=2", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{ListType: "2"}, http.Header{}, OperationListObjects},
		{"bucket-level get versioning", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasVersioning: true}, http.Header{}, OperationGetBucketVersioning},
		{"bucket-level put versioning", http.MethodPut, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasVersioning: true}, http.Header{}, OperationPutBucketVersioning},
		{"bucket-level get policy", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasPolicy: true}, http.Header{}, OperationGetBucketPolicy},
		{"bucket-level put policy", http.MethodPut, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasPolicy: true}, http.Header{}, OperationPutBucketPolicy},
		{"bucket-level delete policy", http.MethodDelete, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasPolicy: true}, http.Header{}, OperationDeleteBucketPolicy},
		{"bucket-level get policy status", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasPolicyStatus: true}, http.Header{}, OperationGetBucketPolicyStatus},
		{"bucket-level get lifecycle", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasLifecycle: true}, http.Header{}, OperationGetBucketLifecycle},
		{"bucket-level put lifecycle", http.MethodPut, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasLifecycle: true}, http.Header{}, OperationPutBucketLifecycle},
		{"bucket-level delete lifecycle", http.MethodDelete, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasLifecycle: true}, http.Header{}, OperationDeleteBucketLifecycle},
		{"bucket-level get acl", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasACL: true}, http.Header{}, OperationGetBucketACL},
		{"bucket-level put acl", http.MethodPut, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasACL: true}, http.Header{}, OperationPutBucketACL},
		{"bucket-level list-objects with explicit list-type key", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasListType: true, ListType: "1"}, http.Header{}, OperationListObjects},
		{"bucket-level create (no query)", http.MethodPut, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{}, http.Header{}, OperationCreateBucket},
		{"bucket-level delete (no query)", http.MethodDelete, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{}, http.Header{}, OperationDeleteBucket},
		{"bucket-level head", http.MethodHead, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{}, http.Header{}, OperationHeadBucket},
		{"bucket-level list multipart uploads", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasUploads: true}, http.Header{}, OperationListMultipartUploads},
		{"bucket-level list object versions", http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasVersions: true}, http.Header{}, OperationListObjectVersions},

		// --- object-level operations (target.Key != "") ---
		{"object-level get acl", http.MethodGet, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasACL: true}, http.Header{}, OperationGetObjectACL},
		{"object-level put acl", http.MethodPut, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasACL: true}, http.Header{}, OperationPutObjectACL},
		{"object-level copy via header", http.MethodPut, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{}, func() http.Header { h := http.Header{}; h.Set("X-Amz-Copy-Source", "/src/key"); return h }(), OperationCopyObject},
		{"object-level copy via query", http.MethodPut, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasCopySource: true}, http.Header{}, OperationCopyObject},
		{"object-level create multipart upload", http.MethodPost, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasUploads: true}, http.Header{}, OperationCreateMultipartUpload},
		{"object-level upload part", http.MethodPut, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasUploadID: true, HasPartNumber: true, UploadID: "u1", PartNumber: "1"}, http.Header{}, OperationUploadPart},
		{"object-level complete multipart", http.MethodPost, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasUploadID: true, UploadID: "u1"}, http.Header{}, OperationCompleteMultipartUpload},
		{"object-level abort multipart", http.MethodDelete, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasUploadID: true, UploadID: "u1"}, http.Header{}, OperationAbortMultipartUpload},
		{"object-level list parts", http.MethodGet, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasUploadID: true, UploadID: "u1"}, http.Header{}, OperationListParts},
		{"object-level put malformed part (no uploadId)", http.MethodPut, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{HasPartNumber: true, PartNumber: "1"}, http.Header{}, OperationUnknown},
		{"object-level head", http.MethodHead, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{}, http.Header{}, OperationHeadObject},
		{"object-level get (default)", http.MethodGet, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{}, http.Header{}, OperationGetObject},
		{"object-level delete (default)", http.MethodDelete, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{}, http.Header{}, OperationDeleteObject},
		{"object-level put (default)", http.MethodPut, RequestTarget{Bucket: "bucket", Key: "k"}, DispatchQuery{}, http.Header{}, OperationPutObject},

		// --- root-level operations ---
		{"root-level list buckets", http.MethodGet, RequestTarget{}, DispatchQuery{}, http.Header{}, OperationListBuckets},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			op := ResolveOperation(tc.method, tc.target, tc.query, tc.headers)
			if op != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, op)
			}
		})
	}
}

func TestParseRequestTargetPathStyleEmptyBucket(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://storage.local/", nil)
	target, err := ParseRequestTarget(r, "storage.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Bucket != "" {
		t.Fatalf("expected empty bucket for root path, got %q", target.Bucket)
	}
	if target.Key != "" {
		t.Fatalf("expected empty key for root path, got %q", target.Key)
	}
	if target.Style != AddressingPathStyle {
		t.Fatalf("expected path style for root path, got %s", target.Style)
	}
}

func TestRouterAddsRequestIDAndHealth(t *testing.T) {
	t.Parallel()
	router := NewRouter(RouterConfig{ServiceHost: "storage.local"})

	req := httptest.NewRequest(http.MethodGet, "http://storage.local/healthz", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if res.Header().Get("X-Request-Id") == "" {
		t.Fatal("expected X-Request-Id header")
	}
}

func TestRouterHealthOnlyAllowsGET(t *testing.T) {
	t.Parallel()
	router := NewRouter(RouterConfig{ServiceHost: "storage.local"})

	req := httptest.NewRequest(http.MethodPost, "http://storage.local/healthz", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", res.Code)
	}
	if res.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("expected Allow=GET, got %q", res.Header().Get("Allow"))
	}

	req = httptest.NewRequest(http.MethodHead, "http://storage.local/readyz", nil)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", res.Code)
	}
	if res.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("expected Allow=GET, got %q", res.Header().Get("Allow"))
	}
}

func TestGenerateRequestIDFormat(t *testing.T) {
	t.Parallel()
	reqID := GenerateRequestID()
	matched, err := regexp.MatchString(`^req-\d+-[0-9a-f]{16}$`, reqID)
	if err != nil {
		t.Fatalf("regexp compile: %v", err)
	}
	if !matched {
		t.Fatalf("unexpected request id format: %q", reqID)
	}
}

func TestParseDispatchQueryMultipartFields(t *testing.T) {
	t.Parallel()
	q := ParseDispatchQuery(map[string][]string{
		"list-type":          {"2"},
		"uploads":            {""},
		"uploadId":           {"u1"},
		"partNumber":         {"2"},
		"key-marker":         {"k"},
		"upload-id-marker":   {"u0"},
		"max-uploads":        {"10"},
		"part-number-marker": {"1"},
		"max-parts":          {"5"},
		"x-amz-copy-source":  {""},
		"versions":           {""},
		"versioning":         {""},
		"policy":             {""},
		"policyStatus":       {""},
		"lifecycle":          {""},
		"acl":                {""},
	})
	if !q.HasUploads || q.UploadID != "u1" || q.PartNumber != "2" || q.MaxParts != "5" {
		t.Fatalf("unexpected multipart dispatch query: %+v", q)
	}
	if !q.HasUploadID || !q.HasPartNumber {
		t.Fatalf("expected multipart query presence flags, got %+v", q)
	}
	if !q.HasCopySource {
		t.Fatalf("expected copy-source presence flag, got %+v", q)
	}
	if !q.HasListType {
		t.Fatalf("expected list-type presence flag, got %+v", q)
	}
	if !q.HasVersions || !q.HasVersioning || !q.HasPolicy || !q.HasPolicyStatus || !q.HasLifecycle || !q.HasACL {
		t.Fatalf("expected versions/versioning/policy/policyStatus/lifecycle/acl presence flags, got %+v", q)
	}
}

type writeFailingRecorder struct {
	httptest.ResponseRecorder
	err error
}

func (w *writeFailingRecorder) Write(p []byte) (int, error) {
	return 0, w.err
}

func TestRouterLogsWriteFailureOnLivenessEndpoint(t *testing.T) {
	t.Parallel()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	router := NewRouter(RouterConfig{ServiceHost: "storage.local", Logger: logger})

	req := httptest.NewRequest(http.MethodGet, "http://storage.local/healthz", nil)
	res := &writeFailingRecorder{ResponseRecorder: *httptest.NewRecorder(), err: errors.New("simulated write failure")}
	router.ServeHTTP(res, req)

	if !strings.Contains(logBuf.String(), "failed to write response body") {
		t.Fatalf("expected write failure log entry, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "liveness") {
		t.Fatalf("expected log to identify liveness endpoint, got: %s", logBuf.String())
	}
}

func TestRouterNilLoggerDoesNotPanicOnWriteFailure(t *testing.T) {
	t.Parallel()
	router := NewRouter(RouterConfig{ServiceHost: "storage.local"})

	req := httptest.NewRequest(http.MethodGet, "http://storage.local/healthz", nil)
	res := &writeFailingRecorder{ResponseRecorder: *httptest.NewRecorder(), err: errors.New("simulated write failure")}
	router.ServeHTTP(res, req)
}
