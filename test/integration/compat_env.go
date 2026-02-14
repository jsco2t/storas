package integration

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"storas/internal/api"
	"storas/internal/authz"
	"storas/internal/sigv4"
	"storas/internal/storage"
)

type CompatEnv struct {
	t       *testing.T
	handler http.Handler
	now     time.Time
	server  *httptest.Server
}

func NewCompatEnv(t *testing.T) *CompatEnv {
	t.Helper()
	now := time.Now().UTC()
	backend, err := storage.NewFSBackend(filepath.Join(t.TempDir(), "data"), 25*1024*1024*1024)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	authPath := filepath.Join(t.TempDir(), "authorization.yaml")
	if err := os.WriteFile(authPath, []byte(authYAMLCompat), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	engine, err := authz.LoadFile(authPath)
	if err != nil {
		t.Fatalf("LoadFile authz error: %v", err)
	}
	svc := &api.Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 24 * time.Hour, ServiceHost: "", Now: time.Now}
	h := svc.Handler()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &CompatEnv{t: t, handler: h, now: now, server: srv}
}

func (e *CompatEnv) BaseURL() string { return e.server.URL }

func (e *CompatEnv) MustReq(t *testing.T, method, path string, body io.Reader, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := e.newSignedRequest(method, path, body, "AKIAFULL", "secret-full", "")
	res := httptest.NewRecorder()
	e.handler.ServeHTTP(res, req)
	if res.Code != want {
		t.Fatalf("unexpected status=%d want=%d path=%s body=%s", res.Code, want, path, res.Body.String())
	}
	return res
}

func (e *CompatEnv) newSignedRequest(method, path string, body io.Reader, accessKey, secret, host string) *http.Request {
	e.t.Helper()
	req := httptest.NewRequest(method, "http://storage.local"+path, body)
	if host != "" {
		req.Host = host
	}
	payloadHash := "UNSIGNED-PAYLOAD"
	req.Header.Set("X-Amz-Date", e.now.UTC().Format(sigv4.DateFormat))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}

	canonical, err := sigv4.BuildCanonicalRequest(req, signedHeaders, payloadHash)
	if err != nil {
		e.t.Fatalf("BuildCanonicalRequest: %v", err)
	}
	scope := sigv4.CredentialScope{AccessKey: accessKey, Date: e.now.UTC().Format("20060102"), Region: "us-west-1", Service: "s3", Terminal: "aws4_request"}
	stringToSign := sigv4.BuildStringToSign(canonical, e.now.UTC(), scope)
	sig := sigv4.SignatureHex(sigv4.SigningKey(secret, scope.Date, scope.Region, scope.Service), stringToSign)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+scope.AccessKey+"/"+scope.Date+"/"+scope.Region+"/"+scope.Service+"/"+scope.Terminal+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+sig)
	return req
}

func (e *CompatEnv) Upload(bucket, key, value string) {
	e.MustReq(e.t, http.MethodPut, "/"+bucket, nil, http.StatusOK)
	e.MustReq(e.t, http.MethodPut, "/"+bucket+"/"+key, bytes.NewBufferString(value), http.StatusOK)
}

const authYAMLCompat = `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:list"
        resource: "*"
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:delete"
        resource: "*"
      - action: "bucket:head"
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
