package s3

import (
	"bytes"
	"context"
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

func TestParseRequestTargetRootPath(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://storage.local/", nil)
	target, err := ParseRequestTarget(r, "")
	if err != nil {
		t.Fatalf("ParseRequestTarget root path error: %v", err)
	}
	if target.Style != AddressingPathStyle {
		t.Fatalf("expected path style, got %s", target.Style)
	}
	if target.Bucket != "" || target.Key != "" {
		t.Fatalf("expected empty bucket and key for root path, got %+v", target)
	}
}

func TestParseRequestTargetInvalidBucket(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://storage.local/UPPERCASE/file.txt", nil)
	_, err := ParseRequestTarget(r, "")
	if err == nil {
		t.Fatal("expected error for invalid bucket name")
	}
	if !errors.Is(err, ErrInvalidRequestPath) {
		t.Fatalf("expected ErrInvalidRequestPath, got %v", err)
	}
}

func TestParseRequestTargetBucketOnlyPath(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://storage.local/mybucket", nil)
	target, err := ParseRequestTarget(r, "")
	if err != nil {
		t.Fatalf("ParseRequestTarget bucket-only path error: %v", err)
	}
	if target.Style != AddressingPathStyle {
		t.Fatalf("expected path style, got %s", target.Style)
	}
	if target.Bucket != "mybucket" {
		t.Fatalf("expected bucket 'mybucket', got %q", target.Bucket)
	}
	if target.Key != "" {
		t.Fatalf("expected empty key for bucket-only path, got %q", target.Key)
	}
}

func TestResolveOperation(t *testing.T) {
	t.Parallel()
	target := RequestTarget{Bucket: "bucket", Key: ""}
	op := ResolveOperation(http.MethodGet, target, DispatchQuery{ListType: "2"}, http.Header{})
	if op != OperationListObjects {
		t.Fatalf("expected list objects, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasVersioning: true}, http.Header{})
	if op != OperationGetBucketVersioning {
		t.Fatalf("expected get bucket versioning, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasVersioning: true}, http.Header{})
	if op != OperationPutBucketVersioning {
		t.Fatalf("expected put bucket versioning, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasPolicy: true}, http.Header{})
	if op != OperationGetBucketPolicy {
		t.Fatalf("expected get bucket policy, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasPolicy: true}, http.Header{})
	if op != OperationPutBucketPolicy {
		t.Fatalf("expected put bucket policy, got %s", op)
	}
	op = ResolveOperation(http.MethodDelete, target, DispatchQuery{HasPolicy: true}, http.Header{})
	if op != OperationDeleteBucketPolicy {
		t.Fatalf("expected delete bucket policy, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasPolicyStatus: true}, http.Header{})
	if op != OperationGetBucketPolicyStatus {
		t.Fatalf("expected get bucket policy status, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasLifecycle: true}, http.Header{})
	if op != OperationGetBucketLifecycle {
		t.Fatalf("expected get bucket lifecycle, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasLifecycle: true}, http.Header{})
	if op != OperationPutBucketLifecycle {
		t.Fatalf("expected put bucket lifecycle, got %s", op)
	}
	op = ResolveOperation(http.MethodDelete, target, DispatchQuery{HasLifecycle: true}, http.Header{})
	if op != OperationDeleteBucketLifecycle {
		t.Fatalf("expected delete bucket lifecycle, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasACL: true}, http.Header{})
	if op != OperationGetBucketACL {
		t.Fatalf("expected get bucket acl, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasACL: true}, http.Header{})
	if op != OperationPutBucketACL {
		t.Fatalf("expected put bucket acl, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasListType: true, ListType: "1"}, http.Header{})
	if op != OperationListObjects {
		t.Fatalf("expected list objects dispatch for explicit list-type key, got %s", op)
	}

	target = RequestTarget{Bucket: "bucket", Key: "k"}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasACL: true}, http.Header{})
	if op != OperationGetObjectACL {
		t.Fatalf("expected get object acl, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasACL: true}, http.Header{})
	if op != OperationPutObjectACL {
		t.Fatalf("expected put object acl, got %s", op)
	}
	h := make(http.Header)
	h.Set("X-Amz-Copy-Source", "/src/key")
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{}, h)
	if op != OperationCopyObject {
		t.Fatalf("expected copy object, got %s", op)
	}

	op = ResolveOperation(http.MethodPost, target, DispatchQuery{HasUploads: true}, http.Header{})
	if op != OperationCreateMultipartUpload {
		t.Fatalf("expected create multipart upload, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasUploadID: true, HasPartNumber: true, UploadID: "u1", PartNumber: "1"}, http.Header{})
	if op != OperationUploadPart {
		t.Fatalf("expected upload part, got %s", op)
	}
	op = ResolveOperation(http.MethodPost, target, DispatchQuery{HasUploadID: true, UploadID: "u1"}, http.Header{})
	if op != OperationCompleteMultipartUpload {
		t.Fatalf("expected complete multipart upload, got %s", op)
	}
	op = ResolveOperation(http.MethodDelete, target, DispatchQuery{HasUploadID: true, UploadID: "u1"}, http.Header{})
	if op != OperationAbortMultipartUpload {
		t.Fatalf("expected abort multipart upload, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{HasUploads: true}, http.Header{})
	if op != OperationListMultipartUploads {
		t.Fatalf("expected list multipart uploads, got %s", op)
	}
	op = ResolveOperation(http.MethodGet, target, DispatchQuery{HasUploadID: true, UploadID: "u1"}, http.Header{})
	if op != OperationListParts {
		t.Fatalf("expected list parts, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasPartNumber: true, PartNumber: "1"}, http.Header{})
	if op != OperationUnknown {
		t.Fatalf("expected unknown for malformed upload part request, got %s", op)
	}
	op = ResolveOperation(http.MethodPut, target, DispatchQuery{HasCopySource: true}, http.Header{})
	if op != OperationCopyObject {
		t.Fatalf("expected copy object for query copy source presence, got %s", op)
	}

	// Missing bucket-key paths
	t.Run("basic CRUD with no query params", func(t *testing.T) {
		t.Parallel()
		op := ResolveOperation(http.MethodPut, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{}, http.Header{})
		if op != OperationCreateBucket {
			t.Fatalf("expected create bucket, got %s", op)
		}
		op = ResolveOperation(http.MethodPut, RequestTarget{Bucket: "bucket", Key: "myfile"}, DispatchQuery{}, http.Header{})
		if op != OperationPutObject {
			t.Fatalf("expected put object, got %s", op)
		}
		op = ResolveOperation(http.MethodGet, RequestTarget{Bucket: "bucket", Key: "myfile"}, DispatchQuery{}, http.Header{})
		if op != OperationGetObject {
			t.Fatalf("expected get object, got %s", op)
		}
		op = ResolveOperation(http.MethodDelete, RequestTarget{Bucket: "bucket", Key: "myfile"}, DispatchQuery{}, http.Header{})
		if op != OperationDeleteObject {
			t.Fatalf("expected delete object, got %s", op)
		}
	})

	// Unknown method returns OperationUnknown
	t.Run("unknown method returns OperationUnknown", func(t *testing.T) {
		t.Parallel()
		op := ResolveOperation(http.MethodPatch, RequestTarget{Bucket: "bucket", Key: ""}, DispatchQuery{}, http.Header{})
		if op != OperationUnknown {
			t.Fatalf("expected unknown for PATCH method, got %s", op)
		}
		op = ResolveOperation(http.MethodPatch, RequestTarget{Bucket: "bucket", Key: "file"}, DispatchQuery{}, http.Header{})
		if op != OperationUnknown {
			t.Fatalf("expected unknown for PATCH method with key, got %s", op)
		}
	})
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

func TestRouterCustomHealthPaths(t *testing.T) {
	t.Parallel()
	router := NewRouter(RouterConfig{
		ServiceHost: "storage.local",
		PathLive:    "/live",
		PathReady:   "/ready",
	})

	// Custom live path works
	req := httptest.NewRequest(http.MethodGet, "http://storage.local/live", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 on custom live path, got %d", res.Code)
	}

	// Custom ready path works
	req = httptest.NewRequest(http.MethodGet, "http://storage.local/ready", nil)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 on custom ready path, got %d", res.Code)
	}

	// Default /healthz is not registered as a health path, so it hits the catch-all
	// which returns 501 because no Handler is configured
	req = httptest.NewRequest(http.MethodGet, "http://storage.local/healthz", nil)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 on default path when custom paths set, got %d", res.Code)
	}
}

func TestRouterReadyCheckFailure(t *testing.T) {
	t.Parallel()
	router := NewRouter(RouterConfig{
		ServiceHost: "storage.local",
		ReadyCheck: func() error {
			return errors.New("disk full")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://storage.local/readyz", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on ready check failure, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "disk full") {
		t.Fatalf("expected error body, got %q", res.Body.String())
	}
}

func TestRouterCustomHandler(t *testing.T) {
	t.Parallel()
	var gotTarget RequestTarget
	var gotOp Operation
	router := NewRouter(RouterConfig{
		ServiceHost: "storage.local",
		Handler: func(w http.ResponseWriter, r *http.Request, target RequestTarget, op Operation) {
			gotTarget = target
			gotOp = op
			w.WriteHeader(http.StatusOK)
		},
	})

	req := httptest.NewRequest(http.MethodPut, "http://storage.local/mybucket/mykey", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if gotTarget.Bucket != "mybucket" {
		t.Fatalf("expected bucket 'mybucket', got %q", gotTarget.Bucket)
	}
	if gotTarget.Key != "mykey" {
		t.Fatalf("expected key 'mykey', got %q", gotTarget.Key)
	}
	if gotOp != OperationPutObject {
		t.Fatalf("expected put object, got %s", gotOp)
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

func TestParseDispatchQueryListFields(t *testing.T) {
	t.Parallel()
	q := ParseDispatchQuery(map[string][]string{
		"delimiter":          {"/"},
		"prefix":             {"logs/"},
		"continuation-token": {"token123"},
		"max-keys":           {"100"},
	})
	if q.Delimiter != "/" {
		t.Fatalf("expected delimiter '/', got %q", q.Delimiter)
	}
	if q.Prefix != "logs/" {
		t.Fatalf("expected prefix 'logs/', got %q", q.Prefix)
	}
	if q.Continuation != "token123" {
		t.Fatalf("expected continuation 'token123', got %q", q.Continuation)
	}
	if q.MaxKeys != "100" {
		t.Fatalf("expected max-keys '100', got %q", q.MaxKeys)
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

func TestRequestIDFromContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Missing key returns empty string
	if got := RequestIDFromContext(ctx); got != "" {
		t.Fatalf("expected empty string for missing key, got %q", got)
	}

	// Valid request ID from context
	reqID := "req-12345-abcdef0123456789"
	ctx = context.WithValue(ctx, requestIDContextKey, reqID)
	if got := RequestIDFromContext(ctx); got != reqID {
		t.Fatalf("expected %q, got %q", reqID, got)
	}

	// Wrong key type returns empty string
	ctx2 := context.WithValue(context.Background(), "not_a_context_key", reqID)
	if got := RequestIDFromContext(ctx2); got != "" {
		t.Fatalf("expected empty string for wrong key type, got %q", got)
	}
}
