package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"storas/internal/authz"
	"storas/internal/policy"
	"storas/internal/s3"
	"storas/internal/sigv4"
	"storas/internal/storage"
)

func TestServiceAuthFailuresAndAccessDenied(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "readonly"
    access_key: "AKIAREAD"
    secret_key: "secret-read"
    allow:
      - action: "bucket:list"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	signRequest(t, req, now, "AKIAUNKNOWN", "secret-read", "us-west-1", "s3")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if !strings.Contains(res.Body.String(), "InvalidAccessKeyId") {
		t.Fatalf("expected InvalidAccessKeyId, body=%s", res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPut, "http://localhost/private-bucket", nil)
	signRequest(t, req, now, "AKIAREAD", "secret-read", "us-west-1", "s3")
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if !strings.Contains(res.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied, body=%s", res.Body.String())
	}
}

func TestServiceLogsExcludeSecretsAndAuthHeaders(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-very-sensitive-token"
    allow:
      - action: "bucket:list"
        resource: "*"
`)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
		Logger:      logger,
	}

	req := signedReq(t, now, http.MethodGet, "http://localhost/", nil, "AKIAFULL", "secret-very-sensitive-token")
	res := httptest.NewRecorder()
	svc.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status=%d body=%s", res.Code, res.Body.String())
	}

	logs := logBuf.String()
	if strings.Contains(logs, "secret-very-sensitive-token") {
		t.Fatalf("log output leaked secret token: %s", logs)
	}
	if strings.Contains(strings.ToLower(logs), "authorization") {
		t.Fatalf("log output leaked authorization header details: %s", logs)
	}
}

func TestServiceBucketAndObjectHandlers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
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
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/backup-a", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/backup-b", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	put := signedReq(t, now, http.MethodPut, "http://localhost/backup-a/dir/file.txt", bytes.NewBufferString("hello-world"), "AKIAFULL", "secret-full")
	put.Header.Set("Content-Type", "text/plain")
	put.Header.Set("x-amz-meta-owner", "qa")
	putRes := mustRequest(t, h, put, http.StatusOK)
	if putRes.Header().Get("ETag") == "" {
		t.Fatal("expected ETag header on PutObject")
	}

	listRes := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/backup-a?list-type=2&prefix=dir/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(listRes.Body.String(), "ListBucketResult") {
		t.Fatalf("expected list bucket XML, body=%s", listRes.Body.String())
	}

	getRes := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/backup-a/dir/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if got := getRes.Body.String(); got != "hello-world" {
		t.Fatalf("unexpected get payload: %q", got)
	}

	rangeReq := signedReq(t, now, http.MethodGet, "http://localhost/backup-a/dir/file.txt", nil, "AKIAFULL", "secret-full")
	rangeReq.Header.Set("Range", "bytes=0-4")
	rangeRes := mustRequest(t, h, rangeReq, http.StatusPartialContent)
	if got := rangeRes.Body.String(); got != "hello" {
		t.Fatalf("unexpected range payload: %q", got)
	}
	if rangeRes.Header().Get("Content-Length") != "5" {
		t.Fatalf("expected range content-length=5, got %q", rangeRes.Header().Get("Content-Length"))
	}
	if rangeRes.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatalf("expected Accept-Ranges=bytes, got %q", rangeRes.Header().Get("Accept-Ranges"))
	}

	headRes := mustRequest(t, h, signedReq(t, now, http.MethodHead, "http://localhost/backup-a/dir/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if headRes.Header().Get("x-amz-meta-owner") != "qa" {
		t.Fatalf("expected x-amz-meta-owner header, got %q", headRes.Header().Get("x-amz-meta-owner"))
	}
	if headRes.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatalf("expected Accept-Ranges=bytes, got %q", headRes.Header().Get("Accept-Ranges"))
	}

	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/backup-b/copied.txt", nil, "AKIAFULL", "secret-full")
	copyReq.Header.Set("X-Amz-Copy-Source", "/backup-a/dir/file.txt")
	copyRes := mustRequest(t, h, copyReq, http.StatusOK)
	if !strings.Contains(copyRes.Body.String(), "CopyObjectResult") {
		t.Fatalf("expected copy XML body, got %s", copyRes.Body.String())
	}

	mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/backup-a/dir/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusNoContent)
	mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/backup-a/dir/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusNoContent)

	bucketDelete := mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/backup-b", nil, "AKIAFULL", "secret-full"), http.StatusConflict)
	if !strings.Contains(bucketDelete.Body.String(), "BucketNotEmpty") {
		t.Fatalf("expected BucketNotEmpty, got %s", bucketDelete.Body.String())
	}

	listBuckets := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	var parsed struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	}
	if err := xml.Unmarshal(listBuckets.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("list buckets XML parse: %v", err)
	}
}

func TestServicePutObjectHonorsBodySizeLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngineWithLimit(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
`, 5)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/backup-a", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	res := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/backup-a/too-big.txt", bytes.NewBufferString("123456"), "AKIAFULL", "secret-full"), http.StatusRequestEntityTooLarge)
	if !strings.Contains(res.Body.String(), "EntityTooLarge") {
		t.Fatalf("expected EntityTooLarge body, got %s", res.Body.String())
	}
}

func TestServicePutObjectHonorsHTTPBodyLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngineWithLimit(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
`, 25*1024*1024*1024)
	svc := &Service{
		Backend:      backend,
		Authz:        engine,
		Region:       "us-west-1",
		ServiceName:  "s3",
		ClockSkew:    15 * time.Minute,
		Now:          func() time.Time { return now },
		MaxBodyBytes: 5,
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/http-limit-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	res := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/http-limit-bucket/too-big.txt", bytes.NewBufferString("123456"), "AKIAFULL", "secret-full"), http.StatusRequestEntityTooLarge)
	if !strings.Contains(res.Body.String(), "EntityTooLarge") {
		t.Fatalf("expected EntityTooLarge body, got %s", res.Body.String())
	}
}

func TestServicePutBucketPolicyRejectsOversizedPolicyDocument(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
`)
	svc := &Service{
		Backend:      backend,
		Authz:        engine,
		Region:       "us-west-1",
		ServiceName:  "s3",
		ClockSkew:    15 * time.Minute,
		Now:          func() time.Time { return now },
		MaxBodyBytes: 25 * 1024 * 1024,
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"%s","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*"}]}`, strings.Repeat("x", 24*1024))
	res := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusRequestEntityTooLarge)
	if !strings.Contains(res.Body.String(), "EntityTooLarge") {
		t.Fatalf("expected EntityTooLarge body, got %s", res.Body.String())
	}
}

func TestServiceListBucketsIncludesOwnerAndCreationDate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:list"
        resource: "*"
      - action: "bucket:create"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/bucket-a", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/bucket-b", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	res := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	body := res.Body.String()
	if !strings.Contains(body, "<Owner>") || !strings.Contains(body, "<DisplayName>local</DisplayName>") {
		t.Fatalf("expected owner in ListBuckets response, got %s", body)
	}
	if strings.Index(body, "<Owner>") > strings.Index(body, "<Buckets>") {
		t.Fatalf("expected Owner element before Buckets element, got %s", body)
	}
	if !strings.Contains(body, "<CreationDate>") {
		t.Fatalf("expected bucket CreationDate field, got %s", body)
	}
}

func TestServiceCreateBucketLocationConstraintSemantics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/create-empty", bytes.NewBufferString(""), "AKIAFULL", "secret-full"), http.StatusOK)

	explicitBody := `<CreateBucketConfiguration><LocationConstraint>us-west-1</LocationConstraint></CreateBucketConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/create-explicit", bytes.NewBufferString(explicitBody), "AKIAFULL", "secret-full"), http.StatusOK)

	mismatchBody := `<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>`
	mismatch := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/create-mismatch", bytes.NewBufferString(mismatchBody), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(mismatch.Body.String(), "IllegalLocationConstraintException") {
		t.Fatalf("expected IllegalLocationConstraintException, got %s", mismatch.Body.String())
	}

	dup := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/create-empty", bytes.NewBufferString(""), "AKIAFULL", "secret-full"), http.StatusConflict)
	if !strings.Contains(dup.Body.String(), "BucketAlreadyOwnedByYou") {
		t.Fatalf("expected duplicate create conflict, got %s", dup.Body.String())
	}
}

func TestServiceDeleteObjectOnMissingBucketReturnsNoSuchBucket(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "object:delete"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	res := mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/missing-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusNotFound)
	if !strings.Contains(res.Body.String(), "NoSuchBucket") {
		t.Fatalf("expected NoSuchBucket, got %s", res.Body.String())
	}
}

func TestServiceProtocolWireFormatETagAndTimestamps(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:list"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/wire-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	put := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/wire-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.HasPrefix(put.Header().Get("ETag"), "\"") || !strings.HasSuffix(put.Header().Get("ETag"), "\"") {
		t.Fatalf("expected quoted ETag header on PutObject, got %q", put.Header().Get("ETag"))
	}

	head := mustRequest(t, h, signedReq(t, now, http.MethodHead, "http://localhost/wire-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.HasPrefix(head.Header().Get("ETag"), "\"") || !strings.HasSuffix(head.Header().Get("ETag"), "\"") {
		t.Fatalf("expected quoted ETag header on HeadObject, got %q", head.Header().Get("ETag"))
	}

	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/wire-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	copyReq.Header.Set("X-Amz-Copy-Source", "/wire-bucket/file.txt")
	copyRes := mustRequest(t, h, copyReq, http.StatusOK)
	var copyOut struct {
		ETag string `xml:"ETag"`
	}
	if err := xml.Unmarshal(copyRes.Body.Bytes(), &copyOut); err != nil {
		t.Fatalf("decode copy response: %v", err)
	}
	if !strings.HasPrefix(copyOut.ETag, "\"") || !strings.HasSuffix(copyOut.ETag, "\"") {
		t.Fatalf("expected quoted ETag in CopyObject XML, got %q body=%s", copyOut.ETag, copyRes.Body.String())
	}

	list := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/wire-bucket?list-type=2", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	timePattern := regexp.MustCompile(`<LastModified>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z</LastModified>`)
	if !timePattern.MatchString(list.Body.String()) {
		t.Fatalf("expected AWS-style XML timestamp in list response, got %s", list.Body.String())
	}
}

func TestServiceResponseCompatibilityRegressionShapes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:list"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	create := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/compat-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if create.Body.Len() != 0 {
		t.Fatalf("expected empty CreateBucket body, got %q", create.Body.String())
	}
	listBuckets := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if ct := listBuckets.Header().Get("Content-Type"); !strings.Contains(ct, "application/xml") {
		t.Fatalf("expected XML content type for ListBuckets, got %q", ct)
	}
	if !strings.Contains(listBuckets.Body.String(), "<ListAllMyBucketsResult") {
		t.Fatalf("expected ListAllMyBucketsResult XML root, got %s", listBuckets.Body.String())
	}

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/compat-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full"), http.StatusOK)
	list := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/compat-bucket?list-type=2", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(list.Body.String(), "<ListBucketResult") {
		t.Fatalf("expected ListBucketResult XML root, got %s", list.Body.String())
	}
	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/compat-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	copyReq.Header.Set("X-Amz-Copy-Source", "/compat-bucket/file.txt")
	copyRes := mustRequest(t, h, copyReq, http.StatusOK)
	if !strings.Contains(copyRes.Body.String(), "<CopyObjectResult>") {
		t.Fatalf("expected CopyObjectResult XML root, got %s", copyRes.Body.String())
	}
}

func TestServiceMultipartHandlers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	createRes := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/file.txt?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(createRes.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart response: %v", err)
	}
	if created.UploadID == "" {
		t.Fatal("expected UploadId")
	}

	part1 := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket/file.txt?partNumber=1&uploadId="+created.UploadID, bytes.NewBufferString("hello "), "AKIAFULL", "secret-full"), http.StatusOK)
	part2 := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket/file.txt?partNumber=2&uploadId="+created.UploadID, bytes.NewBufferString("world"), "AKIAFULL", "secret-full"), http.StatusOK)

	listParts := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket/file.txt?uploadId="+created.UploadID, nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(listParts.Body.String(), "ListPartsResult") {
		t.Fatalf("expected ListPartsResult, got %s", listParts.Body.String())
	}

	completePayload := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + part1.Header().Get("ETag") + `</ETag></Part><Part><PartNumber>2</PartNumber><ETag>` + part2.Header().Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	complete := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/file.txt?uploadId="+created.UploadID, bytes.NewBufferString(completePayload), "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(complete.Body.String(), "CompleteMultipartUploadResult") {
		t.Fatalf("expected complete multipart xml, got %s", complete.Body.String())
	}

	get := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if get.Body.String() != "hello world" {
		t.Fatalf("unexpected object after multipart complete: %q", get.Body.String())
	}
}

func TestServiceMultipartInvalidRequests(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	res := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket/file.txt?uploadId=u1", bytes.NewBufferString("x"), "AKIAFULL", "secret-full"), http.StatusMethodNotAllowed)
	if !strings.Contains(res.Body.String(), "MethodNotAllowed") {
		t.Fatalf("expected MethodNotAllowed for malformed upload part operation, got %s", res.Body.String())
	}

	listUploads := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket?uploads=&max-uploads=-1", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(listUploads.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for max-uploads, got %s", listUploads.Body.String())
	}
	listUploadsMarker := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket?uploads=&upload-id-marker=u1", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(listUploadsMarker.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for upload-id-marker without key-marker, got %s", listUploadsMarker.Body.String())
	}

	create := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/file.txt?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart response: %v", err)
	}
	part := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket/file.txt?partNumber=1&uploadId="+created.UploadID, bytes.NewBufferString("abc"), "AKIAFULL", "secret-full"), http.StatusOK)
	part2 := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket/file.txt?partNumber=2&uploadId="+created.UploadID, bytes.NewBufferString("def"), "AKIAFULL", "secret-full"), http.StatusOK)

	listParts := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket/file.txt?uploadId="+created.UploadID+"&max-parts=5000", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(listParts.Body.String(), "<MaxParts>1000</MaxParts>") {
		t.Fatalf("expected max-parts clamp to 1000, got %s", listParts.Body.String())
	}
	invalidPartMarker := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket/file.txt?uploadId="+created.UploadID+"&part-number-marker=10001", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalidPartMarker.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for part-number-marker > 10000, got %s", invalidPartMarker.Body.String())
	}

	invalidOrder := `<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>` + part2.Header().Get("ETag") + `</ETag></Part><Part><PartNumber>1</PartNumber><ETag>` + part.Header().Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	invalidOrderRes := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/file.txt?uploadId="+created.UploadID, bytes.NewBufferString(invalidOrder), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalidOrderRes.Body.String(), "InvalidPartOrder") {
		t.Fatalf("expected InvalidPartOrder, got %s", invalidOrderRes.Body.String())
	}
}

func TestServiceMultipartListEncodingAndMarkerSemantics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	escapedAKey := strings.ReplaceAll(url.PathEscape("a/space file.txt"), "%2F", "/")

	createA1 := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/"+escapedAKey+"?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	createA2 := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/"+escapedAKey+"?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	_ = mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multipart-bucket/b.txt?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	var a1 struct {
		UploadID string `xml:"UploadId"`
	}
	var a2 struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(createA1.Body.Bytes(), &a1); err != nil {
		t.Fatalf("decode createA1 response: %v", err)
	}
	if err := xml.Unmarshal(createA2.Body.Bytes(), &a2); err != nil {
		t.Fatalf("decode createA2 response: %v", err)
	}
	if a1.UploadID == "" || a2.UploadID == "" {
		t.Fatalf("expected upload IDs in create responses: a1=%q a2=%q", a1.UploadID, a2.UploadID)
	}
	if a2.UploadID < a1.UploadID {
		a1.UploadID, a2.UploadID = a2.UploadID, a1.UploadID
	}

	invalidUploadsEncoding := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket?uploads=&encoding-type=base64", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalidUploadsEncoding.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for unsupported multipart uploads encoding-type, got %s", invalidUploadsEncoding.Body.String())
	}

	uploadsEncoded := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket?uploads=&encoding-type=url&prefix=a/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(uploadsEncoded.Body.String(), "<EncodingType>url</EncodingType>") {
		t.Fatalf("expected encoding-type echo for ListMultipartUploads, got %s", uploadsEncoded.Body.String())
	}
	if !strings.Contains(uploadsEncoded.Body.String(), "<Prefix>a%2F</Prefix>") {
		t.Fatalf("expected encoded prefix for ListMultipartUploads, got %s", uploadsEncoded.Body.String())
	}
	if !strings.Contains(uploadsEncoded.Body.String(), "<Key>a%2Fspace%20file.txt</Key>") {
		t.Fatalf("expected encoded upload key for ListMultipartUploads, got %s", uploadsEncoded.Body.String())
	}

	afterKeyOnly := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket?uploads=&key-marker=a%2Fspace%20file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if strings.Contains(afterKeyOnly.Body.String(), "<Key>a/space file.txt</Key>") {
		t.Fatalf("expected key-marker without upload-id-marker to skip equal-key uploads, got %s", afterKeyOnly.Body.String())
	}

	afterKeyAndUpload := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket?uploads=&key-marker=a%2Fspace%20file.txt&upload-id-marker="+a1.UploadID, nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(afterKeyAndUpload.Body.String(), "<UploadId>"+a2.UploadID+"</UploadId>") {
		t.Fatalf("expected key/upload marker listing to include second upload id, got %s", afterKeyAndUpload.Body.String())
	}

	partUpload := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multipart-bucket/"+escapedAKey+"?partNumber=1&uploadId="+a1.UploadID, bytes.NewBufferString("abc"), "AKIAFULL", "secret-full"), http.StatusOK)
	_ = partUpload
	invalidPartsEncoding := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket/"+escapedAKey+"?uploadId="+a1.UploadID+"&encoding-type=base64", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalidPartsEncoding.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for unsupported ListParts encoding-type, got %s", invalidPartsEncoding.Body.String())
	}
	partsEncoded := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/multipart-bucket/"+escapedAKey+"?uploadId="+a1.UploadID+"&encoding-type=url", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(partsEncoded.Body.String(), "<EncodingType>url</EncodingType>") {
		t.Fatalf("expected encoding-type echo for ListParts, got %s", partsEncoded.Body.String())
	}
	if !strings.Contains(partsEncoded.Body.String(), "<Key>a%2Fspace%20file.txt</Key>") {
		t.Fatalf("expected encoded key for ListParts, got %s", partsEncoded.Body.String())
	}
}

func TestServiceListObjectsMaxKeysValidationAndClamp(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full"), http.StatusOK)

	invalid := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&max-keys=bad", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalid.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for max-keys parse failure, got %s", invalid.Body.String())
	}

	negative := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&max-keys=-1", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(negative.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for negative max-keys, got %s", negative.Body.String())
	}

	clamped := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&max-keys=9999", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(clamped.Body.String(), "<MaxKeys>1000</MaxKeys>") {
		t.Fatalf("expected max-keys clamp to 1000, got %s", clamped.Body.String())
	}

	zero := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&max-keys=0", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(zero.Body.String(), "<MaxKeys>0</MaxKeys>") {
		t.Fatalf("expected max-keys=0 in response, got %s", zero.Body.String())
	}
	if !strings.Contains(zero.Body.String(), "<KeyCount>0</KeyCount>") {
		t.Fatalf("expected keycount 0 for max-keys=0, got %s", zero.Body.String())
	}

	invalidListType := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=1", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalidListType.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for unsupported list-type, got %s", invalidListType.Body.String())
	}
}

func TestServiceListObjectsEncodingAndStartAfterSemantics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	for _, key := range []string{"dir/a b.txt", "dir/z.txt", "plain.txt"} {
		escapedKey := strings.ReplaceAll(url.PathEscape(key), "%2F", "/")
		mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket/"+escapedKey, bytes.NewBufferString("x"), "AKIAFULL", "secret-full"), http.StatusOK)
	}

	invalidEncoding := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&encoding-type=base64", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(invalidEncoding.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for unsupported encoding-type, got %s", invalidEncoding.Body.String())
	}

	startAfterRes := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&start-after=dir/a%20b.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if strings.Contains(startAfterRes.Body.String(), "<Key>dir/a b.txt</Key>") {
		t.Fatalf("expected start-after to exclude marker key, got %s", startAfterRes.Body.String())
	}

	firstPage := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&max-keys=1", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	var firstParsed struct {
		NextContinuationToken string `xml:"NextContinuationToken"`
	}
	if err := xml.Unmarshal(firstPage.Body.Bytes(), &firstParsed); err != nil {
		t.Fatalf("unmarshal first page: %v", err)
	}
	if firstParsed.NextContinuationToken == "" {
		t.Fatalf("expected continuation token, body=%s", firstPage.Body.String())
	}
	secondURL := "http://localhost/list-bucket?list-type=2&max-keys=2&start-after=z.txt&continuation-token=" + firstParsed.NextContinuationToken
	secondPage := mustRequest(t, h, signedReq(t, now, http.MethodGet, secondURL, nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(secondPage.Body.String(), "<ContinuationToken>"+firstParsed.NextContinuationToken+"</ContinuationToken>") {
		t.Fatalf("expected continuation token echo in response, got %s", secondPage.Body.String())
	}
	if !strings.Contains(secondPage.Body.String(), "<StartAfter>z.txt</StartAfter>") {
		t.Fatalf("expected start-after echo in response, got %s", secondPage.Body.String())
	}

	encoded := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&encoding-type=url&prefix=dir/&delimiter=/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(encoded.Body.String(), "<EncodingType>url</EncodingType>") {
		t.Fatalf("expected encoding-type echo, got %s", encoded.Body.String())
	}
	if !strings.Contains(encoded.Body.String(), "<Prefix>dir%2F</Prefix>") {
		t.Fatalf("expected encoded prefix, got %s", encoded.Body.String())
	}
	if !strings.Contains(encoded.Body.String(), "<Delimiter>%2F</Delimiter>") {
		t.Fatalf("expected encoded delimiter, got %s", encoded.Body.String())
	}
	if !strings.Contains(encoded.Body.String(), "<Key>dir%2Fa%20b.txt</Key>") {
		t.Fatalf("expected encoded key in response, got %s", encoded.Body.String())
	}
}

func TestServiceListObjectsKeyCountIncludesCommonPrefixes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	for _, key := range []string{"a/1.txt", "a/2.txt", "b.txt"} {
		mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket/"+key, bytes.NewBufferString("x"), "AKIAFULL", "secret-full"), http.StatusOK)
	}

	res := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&delimiter=/&max-keys=2", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	type listResult struct {
		KeyCount       int      `xml:"KeyCount"`
		Contents       []string `xml:"Contents>Key"`
		CommonPrefixes []string `xml:"CommonPrefixes>Prefix"`
	}
	var parsed listResult
	if err := xml.Unmarshal(res.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal list result: %v", err)
	}
	if parsed.KeyCount != len(parsed.Contents)+len(parsed.CommonPrefixes) {
		t.Fatalf("expected keycount to match contents+commonprefixes, got keycount=%d contents=%d prefixes=%d body=%s", parsed.KeyCount, len(parsed.Contents), len(parsed.CommonPrefixes), res.Body.String())
	}
}

func TestServiceCopyObjectInvalidCopySource(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	invalidEnc := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	invalidEnc.Header.Set("X-Amz-Copy-Source", "/src-bucket/%zz")
	invalidEncRes := mustRequest(t, h, invalidEnc, http.StatusBadRequest)
	if !strings.Contains(invalidEncRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for bad copy source encoding, got %s", invalidEncRes.Body.String())
	}

	invalidQuery := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	invalidQuery.Header.Set("X-Amz-Copy-Source", "/src-bucket/file.txt?other=1")
	invalidQueryRes := mustRequest(t, h, invalidQuery, http.StatusBadRequest)
	if !strings.Contains(invalidQueryRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for unsupported copy-source query params, got %s", invalidQueryRes.Body.String())
	}

	invalidBucket := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	invalidBucket.Header.Set("X-Amz-Copy-Source", "/BadBucket/file.txt")
	invalidBucketRes := mustRequest(t, h, invalidBucket, http.StatusBadRequest)
	if !strings.Contains(invalidBucketRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for invalid source bucket, got %s", invalidBucketRes.Body.String())
	}

	inconsistent := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt?x-amz-copy-source=%2Fsrc-bucket%2Fother.txt", nil, "AKIAFULL", "secret-full")
	inconsistent.Header.Set("X-Amz-Copy-Source", "/src-bucket/file.txt")
	inconsistentRes := mustRequest(t, h, inconsistent, http.StatusBadRequest)
	if !strings.Contains(inconsistentRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for inconsistent header/query copy source, got %s", inconsistentRes.Body.String())
	}
}

func TestServiceLogsCustomHealthPaths(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:list"
        resource: "*"
`)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
		Logger:      logger,
		PathLive:    "/livez",
		PathReady:   "/ready-livez",
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/livez", nil)
	res := httptest.NewRecorder()
	svc.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status=%d body=%s", res.Code, res.Body.String())
	}

	if !strings.Contains(logs.String(), "/livez") {
		t.Fatalf("expected custom liveness path to be logged, logs=%s", logs.String())
	}
}

func TestApplyConditionalHeadersSupportsETagListsAndWildcard(t *testing.T) {
	t.Parallel()
	meta := storage.ObjectMetadata{ETag: "abc123"}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	req.Header.Set("If-Match", "*")
	res := httptest.NewRecorder()
	if handled := applyConditionalHeaders(res, req, meta); handled {
		t.Fatal("expected If-Match wildcard to allow request")
	}

	req = httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	req.Header.Set("If-None-Match", "\"zzz\", \"abc123\"")
	res = httptest.NewRecorder()
	if handled := applyConditionalHeaders(res, req, meta); !handled {
		t.Fatal("expected If-None-Match list match to be handled")
	}
	if res.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", res.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	req.Header.Set("If-Match", "\"zzz\", \"abc123\"")
	res = httptest.NewRecorder()
	if handled := applyConditionalHeaders(res, req, meta); handled {
		t.Fatalf("expected If-Match list with matching ETag to proceed, status=%d", res.Code)
	}
}

func TestParseCopySourceAllowsVersionIDOnly(t *testing.T) {
	t.Parallel()
	bucket, key, err := parseCopySource("/src-bucket/dir/file.txt?versionId=abc123")
	if err != nil {
		t.Fatalf("parseCopySource returned error: %v", err)
	}
	if bucket != "src-bucket" || key != "dir/file.txt" {
		t.Fatalf("unexpected parse result bucket=%q key=%q", bucket, key)
	}
}

func TestServiceCopyObjectSupportsCopySourceQueryParameter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full"), http.StatusOK)

	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt?x-amz-copy-source=%2Fsrc-bucket%2Ffile.txt", nil, "AKIAFULL", "secret-full")
	copyRes := mustRequest(t, h, copyReq, http.StatusOK)
	if !strings.Contains(copyRes.Body.String(), "CopyObjectResult") {
		t.Fatalf("expected copy object result, got %s", copyRes.Body.String())
	}

	getRes := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/dst-bucket/copied.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if got := getRes.Body.String(); got != "hello" {
		t.Fatalf("unexpected copied payload: %q", got)
	}
}

func TestServiceCopyObjectRequiresSourceReadPermission(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full"), http.StatusOK)

	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	copyReq.Header.Set("X-Amz-Copy-Source", "/src-bucket/file.txt")
	copyRes := mustRequest(t, h, copyReq, http.StatusForbidden)
	if !strings.Contains(copyRes.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for missing source read permission, got %s", copyRes.Body.String())
	}
}

func TestServiceReturnsRequestTimeoutForCanceledAndExpiredContext(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:list"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	req := signedReq(t, now, http.MethodGet, "http://localhost/", nil, "AKIAFULL", "secret-full")
	canceledCtx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(canceledCtx)
	res := mustRequest(t, h, req, http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "RequestTimeout") {
		t.Fatalf("expected RequestTimeout for canceled context, got %s", res.Body.String())
	}

	req = signedReq(t, now, http.MethodGet, "http://localhost/", nil, "AKIAFULL", "secret-full")
	expiredCtx, cancelExpired := context.WithDeadline(req.Context(), now.Add(-time.Second))
	defer cancelExpired()
	req = req.WithContext(expiredCtx)
	res = mustRequest(t, h, req, http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "RequestTimeout") {
		t.Fatalf("expected RequestTimeout for deadline exceeded context, got %s", res.Body.String())
	}
}

func TestServiceGetObjectDefaultsContentType(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/default-ct", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/default-ct/file.bin", bytes.NewBufferString("payload"), "AKIAFULL", "secret-full"), http.StatusOK)

	getRes := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/default-ct/file.bin", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if getRes.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("expected default content type, got %q", getRes.Header().Get("Content-Type"))
	}
	headRes := mustRequest(t, h, signedReq(t, now, http.MethodHead, "http://localhost/default-ct/file.bin", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if headRes.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("expected default content type for head, got %q", headRes.Header().Get("Content-Type"))
	}
}

func TestServiceListObjectsInvalidContinuationToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	res := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&continuation-token=!!!!", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for bad continuation-token, got %s", res.Body.String())
	}
}

func TestApplyConditionalHeadersDateConditions(t *testing.T) {
	t.Parallel()
	lastMod := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	meta := storage.ObjectMetadata{ETag: "abc123", LastModified: lastMod}

	unmodifiedReq := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	unmodifiedReq.Header.Set("If-Unmodified-Since", lastMod.Add(-time.Hour).Format(http.TimeFormat))
	unmodifiedRes := httptest.NewRecorder()
	if handled := applyConditionalHeaders(unmodifiedRes, unmodifiedReq, meta); !handled {
		t.Fatal("expected If-Unmodified-Since precondition failure")
	}
	if unmodifiedRes.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", unmodifiedRes.Code)
	}

	modifiedReq := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	modifiedReq.Header.Set("If-Modified-Since", lastMod.Add(time.Hour).Format(http.TimeFormat))
	modifiedRes := httptest.NewRecorder()
	if handled := applyConditionalHeaders(modifiedRes, modifiedReq, meta); !handled {
		t.Fatal("expected If-Modified-Since not modified response")
	}
	if modifiedRes.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", modifiedRes.Code)
	}

	invalidDateReq := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	invalidDateReq.Header.Set("If-Modified-Since", "not-a-date")
	invalidDateRes := httptest.NewRecorder()
	if handled := applyConditionalHeaders(invalidDateRes, invalidDateReq, meta); handled {
		t.Fatalf("expected invalid If-Modified-Since date to be ignored, got status=%d", invalidDateRes.Code)
	}

	subsecondMeta := storage.ObjectMetadata{ETag: "abc123", LastModified: lastMod.Add(500 * time.Millisecond)}
	subsecondReq := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	subsecondReq.Header.Set("If-Modified-Since", lastMod.Format(http.TimeFormat))
	subsecondRes := httptest.NewRecorder()
	if handled := applyConditionalHeaders(subsecondRes, subsecondReq, subsecondMeta); !handled {
		t.Fatal("expected second-precision If-Modified-Since handling")
	}
	if subsecondRes.Code != http.StatusNotModified {
		t.Fatalf("expected 304 with sub-second last-modified precision, got %d", subsecondRes.Code)
	}
}

func TestServiceListObjectsSupportsFetchOwner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/fetch-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/fetch-bucket/file.txt", bytes.NewBufferString("x"), "AKIAFULL", "secret-full"), http.StatusOK)

	res := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/fetch-bucket?list-type=2&fetch-owner=true", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(res.Body.String(), "<Owner>") || !strings.Contains(res.Body.String(), "<ID>local</ID>") {
		t.Fatalf("expected owner fields in list response, got %s", res.Body.String())
	}
}

func TestServiceListObjectsStartAfterWithDelimiterExcludesPriorPrefixes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/startafter-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	for _, key := range []string{"a/1.txt", "b/1.txt", "c.txt"} {
		mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/startafter-bucket/"+key, bytes.NewBufferString("x"), "AKIAFULL", "secret-full"), http.StatusOK)
	}

	res := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/startafter-bucket?list-type=2&delimiter=/&start-after=a/zzz", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if strings.Contains(res.Body.String(), "<Prefix>a/</Prefix>") {
		t.Fatalf("expected start-after to exclude earlier delimiter prefix, got %s", res.Body.String())
	}
}

func TestServiceRejectsConflictingDuplicateQueryValues(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	res := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&max-keys=1&max-keys=2", nil, "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for conflicting duplicate query params, got %s", res.Body.String())
	}
}

func TestServiceRejectsCopySourceConditionalHeaders(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full"), http.StatusOK)

	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/dst-bucket/copied.txt", nil, "AKIAFULL", "secret-full")
	copyReq.Header.Set("X-Amz-Copy-Source", "/src-bucket/file.txt")
	copyReq.Header.Set("x-amz-copy-source-if-match", "\"etag\"")
	res := mustRequest(t, h, copyReq, http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for unsupported copy-source conditionals, got %s", res.Body.String())
	}
}

func TestServiceGetObjectIfRangeMismatchFallsBackToFullBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/range-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/range-bucket/file.txt", bytes.NewBufferString("hello-world"), "AKIAFULL", "secret-full"), http.StatusOK)

	req := signedReq(t, now, http.MethodGet, "http://localhost/range-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	req.Header.Set("Range", "bytes=0-4")
	req.Header.Set("If-Range", "\"different-etag\"")
	res := mustRequest(t, h, req, http.StatusOK)
	if res.Body.String() != "hello-world" {
		t.Fatalf("expected full body when If-Range does not match, got %q", res.Body.String())
	}
}

func TestServiceValidatesContentMD5AndUserMetadataSize(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/md5-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	goodReq := signedReq(t, now, http.MethodPut, "http://localhost/md5-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full")
	sum := md5.Sum([]byte("hello")) //nolint:gosec // test fixture for Content-MD5 compatibility.
	goodReq.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	mustRequest(t, h, goodReq, http.StatusOK)

	badReq := signedReq(t, now, http.MethodPut, "http://localhost/md5-bucket/bad.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full")
	badReq.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString([]byte("not-a-real-md5!!")))
	badRes := mustRequest(t, h, badReq, http.StatusBadRequest)
	if !strings.Contains(badRes.Body.String(), "BadDigest") {
		t.Fatalf("expected BadDigest for invalid content-md5, got %s", badRes.Body.String())
	}

	oversizedMetaReq := signedReq(t, now, http.MethodPut, "http://localhost/md5-bucket/meta.txt", bytes.NewBufferString("x"), "AKIAFULL", "secret-full")
	oversizedMetaReq.Header.Set("x-amz-meta-big", strings.Repeat("v", 3000))
	metaRes := mustRequest(t, h, oversizedMetaReq, http.StatusBadRequest)
	if !strings.Contains(metaRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for oversized metadata, got %s", metaRes.Body.String())
	}
}

func TestParseObjectTaggingHeader(t *testing.T) {
	t.Parallel()
	tags, err := parseObjectTaggingHeader("env=prod&team=ops")
	if err != nil {
		t.Fatalf("parseObjectTaggingHeader error: %v", err)
	}
	if tags["env"] != "prod" || tags["team"] != "ops" {
		t.Fatalf("unexpected parsed tags: %+v", tags)
	}
	if _, err := parseObjectTaggingHeader("env=prod&env=dev"); err == nil {
		t.Fatal("expected duplicate tag key rejection")
	}
	if _, err := parseObjectTaggingHeader("=prod"); err == nil {
		t.Fatal("expected empty key rejection")
	}
}

func TestServiceUploadPartValidatesContentMD5(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/multi-md5", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	createRes := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/multi-md5/file.txt?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(createRes.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart response: %v", err)
	}

	partReq := signedReq(t, now, http.MethodPut, "http://localhost/multi-md5/file.txt?partNumber=1&uploadId="+created.UploadID, bytes.NewBufferString("hello"), "AKIAFULL", "secret-full")
	partReq.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString([]byte("not-a-real-md5!!")))
	res := mustRequest(t, h, partReq, http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "BadDigest") {
		t.Fatalf("expected BadDigest for multipart content-md5 mismatch, got %s", res.Body.String())
	}
}

func TestServiceCompleteMultipartUploadRejectsUnexpectedXMLRoot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/xml-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	createRes := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/xml-bucket/file.txt?uploads=", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(createRes.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart response: %v", err)
	}
	payload := "<WrongRoot><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></WrongRoot>"
	res := mustRequest(t, h, signedReq(t, now, http.MethodPost, "http://localhost/xml-bucket/file.txt?uploadId="+created.UploadID, bytes.NewBufferString(payload), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "InvalidPart") {
		t.Fatalf("expected InvalidPart for unexpected XML root, got %s", res.Body.String())
	}
}

func TestServicePutObjectSupportsSigV4StreamingPayload(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/stream-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	streamReq := signedReqWithPayloadHash(t, now, http.MethodPut, "http://localhost/stream-bucket/file.txt", nil, "AKIAFULL", "secret-full", sigv4.StreamingPayload)
	streamBody := buildStreamingPayloadForRequest(t, streamReq, "secret-full", []string{"hello-", "stream"})
	streamReq.Body = io.NopCloser(strings.NewReader(streamBody))
	streamReq.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len("hello-stream")))
	putRes := mustRequest(t, h, streamReq, http.StatusOK)
	if putRes.Header().Get("ETag") == "" {
		t.Fatalf("expected ETag header, got %v", putRes.Header())
	}

	getRes := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/stream-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if getRes.Body.String() != "hello-stream" {
		t.Fatalf("unexpected payload: %q", getRes.Body.String())
	}
}

func TestServiceStreamingPayloadRejectsInvalidChunkSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/stream-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	req := signedReqWithPayloadHash(t, now, http.MethodPut, "http://localhost/stream-bucket/file.txt", nil, "AKIAFULL", "secret-full", sigv4.StreamingPayload)
	body := buildStreamingPayloadForRequest(t, req, "secret-full", []string{"hello"})
	const marker = "chunk-signature="
	idx := strings.Index(body, marker)
	if idx < 0 || idx+len(marker) >= len(body) {
		t.Fatalf("unexpected streaming payload format: %q", body)
	}
	sigPos := idx + len(marker)
	mutated := []byte(body)
	if mutated[sigPos] == '0' {
		mutated[sigPos] = '1'
	} else {
		mutated[sigPos] = '0'
	}
	body = string(mutated)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len("hello")))
	res := mustRequest(t, h, req, http.StatusForbidden)
	if !strings.Contains(res.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("expected SignatureDoesNotMatch for invalid chunk signature, got %s", res.Body.String())
	}
}

func TestServiceACLCompatibilityEndpointsAndHeaders(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/acl-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	put := signedReq(t, now, http.MethodPut, "http://localhost/acl-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full")
	put.Header.Set("x-amz-acl", "private")
	mustRequest(t, h, put, http.StatusOK)

	getBucketACL := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/acl-bucket?acl", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(getBucketACL.Body.String(), "<AccessControlPolicy") {
		t.Fatalf("expected ACL XML response, got %s", getBucketACL.Body.String())
	}
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/acl-bucket?acl", bytes.NewBufferString("<AccessControlPolicy/>"), "AKIAFULL", "secret-full"), http.StatusOK)

	getObjectACL := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/acl-bucket/file.txt?acl", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(getObjectACL.Body.String(), "<AccessControlPolicy") {
		t.Fatalf("expected object ACL XML response, got %s", getObjectACL.Body.String())
	}
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/acl-bucket/file.txt?acl", bytes.NewBufferString("<AccessControlPolicy/>"), "AKIAFULL", "secret-full"), http.StatusOK)
}

func TestServiceACLGrantHeadersAreRejectedDeterministically(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/grant-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	req := signedReq(t, now, http.MethodPut, "http://localhost/grant-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAFULL", "secret-full")
	req.Header.Set("x-amz-grant-read", `uri="http://acs.amazonaws.com/groups/global/AllUsers"`)
	res := mustRequest(t, h, req, http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for grant header, got %s", res.Body.String())
	}
}

func TestServiceACLCompatibilityDoesNotGrantAccess(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "owner"
    access_key: "AKIAOWNER"
    secret_key: "secret-owner"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
  - name: "reader"
    access_key: "AKIAREADER"
    secret_key: "secret-reader"
    allow:
      - action: "bucket:head"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/noop-acl-bucket", nil, "AKIAOWNER", "secret-owner"), http.StatusOK)
	put := signedReq(t, now, http.MethodPut, "http://localhost/noop-acl-bucket/file.txt", bytes.NewBufferString("hello"), "AKIAOWNER", "secret-owner")
	put.Header.Set("x-amz-acl", "public-read")
	mustRequest(t, h, put, http.StatusOK)

	before := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/noop-acl-bucket/file.txt", nil, "AKIAREADER", "secret-reader"), http.StatusForbidden)
	if !strings.Contains(before.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied before ACL compatibility calls, got %s", before.Body.String())
	}

	putObjectACL := signedReq(t, now, http.MethodPut, "http://localhost/noop-acl-bucket/file.txt?acl", bytes.NewBufferString("<AccessControlPolicy/>"), "AKIAOWNER", "secret-owner")
	putObjectACL.Header.Set("x-amz-acl", "public-read")
	mustRequest(t, h, putObjectACL, http.StatusOK)

	putBucketACL := signedReq(t, now, http.MethodPut, "http://localhost/noop-acl-bucket?acl", bytes.NewBufferString("<AccessControlPolicy/>"), "AKIAOWNER", "secret-owner")
	putBucketACL.Header.Set("x-amz-acl", "public-read")
	mustRequest(t, h, putBucketACL, http.StatusOK)

	after := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/noop-acl-bucket/file.txt", nil, "AKIAREADER", "secret-reader"), http.StatusForbidden)
	if !strings.Contains(after.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied after ACL compatibility calls, got %s", after.Body.String())
	}
}

func TestServiceBucketVersioningStateEndpoints(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/versioning-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	initial := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/versioning-bucket?versioning", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if strings.Contains(initial.Body.String(), "<Status>") {
		t.Fatalf("expected empty status for Off state, got %s", initial.Body.String())
	}

	enableBody := `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/versioning-bucket?versioning", bytes.NewBufferString(enableBody), "AKIAFULL", "secret-full"), http.StatusOK)

	enabled := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/versioning-bucket?versioning", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(enabled.Body.String(), "<Status>Enabled</Status>") {
		t.Fatalf("expected enabled status, got %s", enabled.Body.String())
	}
}

func TestServiceObjectVersioningAndListObjectVersions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:delete"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	enableBody := `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-bucket?versioning", bytes.NewBufferString(enableBody), "AKIAFULL", "secret-full"), http.StatusOK)

	put1 := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-bucket/key.txt", bytes.NewBufferString("v1"), "AKIAFULL", "secret-full"), http.StatusOK)
	v1 := put1.Header().Get("x-amz-version-id")
	if v1 == "" || v1 == "null" {
		t.Fatalf("expected concrete version id, got %q", v1)
	}
	put2 := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-bucket/key.txt", bytes.NewBufferString("v2"), "AKIAFULL", "secret-full"), http.StatusOK)
	v2 := put2.Header().Get("x-amz-version-id")
	if v2 == "" || v2 == v1 {
		t.Fatalf("expected second version id, v1=%q v2=%q", v1, v2)
	}

	latestGet := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/ver-bucket/key.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if latestGet.Body.String() != "v2" {
		t.Fatalf("expected latest body v2, got %q", latestGet.Body.String())
	}
	if latestGet.Header().Get("x-amz-version-id") != v2 {
		t.Fatalf("expected latest x-amz-version-id=%q, got %q", v2, latestGet.Header().Get("x-amz-version-id"))
	}

	v1Get := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/ver-bucket/key.txt?versionId="+url.QueryEscape(v1), nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if v1Get.Body.String() != "v1" {
		t.Fatalf("expected v1 payload, got %q", v1Get.Body.String())
	}

	versions := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/ver-bucket?versions", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(versions.Body.String(), "<ListVersionsResult") {
		t.Fatalf("expected ListVersionsResult XML, got %s", versions.Body.String())
	}
	if !strings.Contains(versions.Body.String(), "<VersionId>"+v1+"</VersionId>") || !strings.Contains(versions.Body.String(), "<VersionId>"+v2+"</VersionId>") {
		t.Fatalf("expected listed versions %q and %q, got %s", v1, v2, versions.Body.String())
	}
}

func TestServiceDeleteObjectVersionHeaders(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:delete"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-del", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	enableBody := `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-del?versioning", bytes.NewBufferString(enableBody), "AKIAFULL", "secret-full"), http.StatusOK)
	put := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ver-del/key.txt", bytes.NewBufferString("v1"), "AKIAFULL", "secret-full"), http.StatusOK)
	v1 := put.Header().Get("x-amz-version-id")

	delCurrent := mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/ver-del/key.txt", nil, "AKIAFULL", "secret-full"), http.StatusNoContent)
	if delCurrent.Header().Get("x-amz-delete-marker") != "true" {
		t.Fatalf("expected delete marker header, got %q", delCurrent.Header().Get("x-amz-delete-marker"))
	}
	if delCurrent.Header().Get("x-amz-version-id") == "" {
		t.Fatal("expected delete marker version id header")
	}

	delExplicit := mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/ver-del/key.txt?versionId="+url.QueryEscape(v1), nil, "AKIAFULL", "secret-full"), http.StatusNoContent)
	if delExplicit.Header().Get("x-amz-version-id") != v1 {
		t.Fatalf("expected deleted version id header %q, got %q", v1, delExplicit.Header().Get("x-amz-version-id"))
	}
}

func TestServiceBucketLifecycleConfigurationEndpoints(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "bucket:delete"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	missing := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/life-bucket?lifecycle", nil, "AKIAFULL", "secret-full"), http.StatusNotFound)
	if !strings.Contains(missing.Body.String(), "NoSuchLifecycleConfiguration") {
		t.Fatalf("expected NoSuchLifecycleConfiguration, got %s", missing.Body.String())
	}

	body := `<LifecycleConfiguration><Rule><ID>rule-a</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(body), "AKIAFULL", "secret-full"), http.StatusOK)

	got := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/life-bucket?lifecycle", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(got.Body.String(), "<LifecycleConfiguration>") || !strings.Contains(got.Body.String(), "<ID>rule-a</ID>") {
		t.Fatalf("unexpected lifecycle get body: %s", got.Body.String())
	}

	badBody := `<LifecycleConfiguration><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>`
	bad := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(badBody), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(bad.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for invalid lifecycle xml, got %s", bad.Body.String())
	}

	tagBody := `<LifecycleConfiguration><Rule><ID>rule-tag</ID><Status>Enabled</Status><Filter><Tag><Key>env</Key><Value>prod</Value></Tag></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(tagBody), "AKIAFULL", "secret-full"), http.StatusOK)
	tagGet := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/life-bucket?lifecycle", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(tagGet.Body.String(), "<Tag><Key>env</Key><Value>prod</Value></Tag>") {
		t.Fatalf("expected lifecycle tag filter round-trip, got %s", tagGet.Body.String())
	}

	andBody := `<LifecycleConfiguration><Rule><ID>rule-and</ID><Status>Enabled</Status><Filter><And><Prefix>logs/</Prefix><Tag><Key>env</Key><Value>prod</Value></Tag><Tag><Key>team</Key><Value>ops</Value></Tag></And></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(andBody), "AKIAFULL", "secret-full"), http.StatusOK)
	andGet := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/life-bucket?lifecycle", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(andGet.Body.String(), "<And>") || !strings.Contains(andGet.Body.String(), "<Prefix>logs/</Prefix>") {
		t.Fatalf("expected lifecycle And filter round-trip, got %s", andGet.Body.String())
	}

	sizeAndDateBody := `<LifecycleConfiguration><Rule><ID>rule-size-date</ID><Status>Enabled</Status><Filter><And><Prefix>logs/</Prefix><Tag><Key>env</Key><Value>prod</Value></Tag><ObjectSizeGreaterThan>3</ObjectSizeGreaterThan><ObjectSizeLessThan>10</ObjectSizeLessThan></And></Filter><Expiration><Date>2026-02-20T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(sizeAndDateBody), "AKIAFULL", "secret-full"), http.StatusOK)
	sizeAndDateGet := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/life-bucket?lifecycle", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(sizeAndDateGet.Body.String(), "<ObjectSizeGreaterThan>3</ObjectSizeGreaterThan>") ||
		!strings.Contains(sizeAndDateGet.Body.String(), "<ObjectSizeLessThan>10</ObjectSizeLessThan>") ||
		!strings.Contains(sizeAndDateGet.Body.String(), "<Date>2026-02-20T00:00:00Z</Date>") {
		t.Fatalf("expected lifecycle size/date filter round-trip, got %s", sizeAndDateGet.Body.String())
	}

	badSizeWindow := `<LifecycleConfiguration><Rule><ID>bad-size</ID><Status>Enabled</Status><Filter><And><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan><ObjectSizeLessThan>10</ObjectSizeLessThan></And></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`
	badSizeWindowRes := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(badSizeWindow), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(badSizeWindowRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for invalid size window, got %s", badSizeWindowRes.Body.String())
	}

	badDaysAndDate := `<LifecycleConfiguration><Rule><ID>bad-expiry</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>1</Days><Date>2026-02-20</Date></Expiration></Rule></LifecycleConfiguration>`
	badDaysAndDateRes := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/life-bucket?lifecycle", bytes.NewBufferString(badDaysAndDate), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(badDaysAndDateRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for simultaneous expiration Days and Date, got %s", badDaysAndDateRes.Body.String())
	}

	mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/life-bucket?lifecycle", nil, "AKIAFULL", "secret-full"), http.StatusNoContent)
}

func TestServiceBucketPolicyEndpointsAndStatus(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "bucket:delete"
        resource: "*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	missing := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/policy-bucket?policy", nil, "AKIAFULL", "secret-full"), http.StatusNotFound)
	if !strings.Contains(missing.Body.String(), "NoSuchBucketPolicy") {
		t.Fatalf("expected NoSuchBucketPolicy, got %s", missing.Body.String())
	}

	bad := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}]}`
	badRes := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket?policy", bytes.NewBufferString(bad), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(badRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for cross-bucket policy resource, got %s", badRes.Body.String())
	}
	badCIDR := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*","Condition":{"IpAddress":{"aws:SourceIp":"bad-cidr"}}}]}`
	badCIDRRes := mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket?policy", bytes.NewBufferString(badCIDR), "AKIAFULL", "secret-full"), http.StatusBadRequest)
	if !strings.Contains(badCIDRRes.Body.String(), "InvalidRequest") {
		t.Fatalf("expected InvalidRequest for malformed CIDR condition, got %s", badCIDRRes.Body.String())
	}

	valid := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*"}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket?policy", bytes.NewBufferString(valid), "AKIAFULL", "secret-full"), http.StatusNoContent)

	got := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/policy-bucket?policy", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(got.Body.String(), `"Statement"`) {
		t.Fatalf("expected persisted policy json, got %s", got.Body.String())
	}

	status := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/policy-bucket?policyStatus", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(status.Body.String(), "<IsPublic>true</IsPublic>") {
		t.Fatalf("expected public policy status, got %s", status.Body.String())
	}
	conditionalPublic := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/policy-bucket?policy", bytes.NewBufferString(conditionalPublic), "AKIAFULL", "secret-full"), http.StatusNoContent)
	conditionalStatus := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/policy-bucket?policyStatus", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(conditionalStatus.Body.String(), "<IsPublic>true</IsPublic>") {
		t.Fatalf("expected conditional public policy status to be true, got %s", conditionalStatus.Body.String())
	}

	mustRequest(t, h, signedReq(t, now, http.MethodDelete, "http://localhost/policy-bucket?policy", nil, "AKIAFULL", "secret-full"), http.StatusNoContent)
	missingAfterDelete := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/policy-bucket?policy", nil, "AKIAFULL", "secret-full"), http.StatusNotFound)
	if !strings.Contains(missingAfterDelete.Body.String(), "NoSuchBucketPolicy") {
		t.Fatalf("expected NoSuchBucketPolicy after delete, got %s", missingAfterDelete.Body.String())
	}
}

func TestServiceBucketPolicyAuthorizationEnforcement(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
`)
	svc := &Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, Now: func() time.Time { return now }}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/dst", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src/public.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src/private.txt", bytes.NewBufferString("secret"), "AKIAFULL", "secret-full"), http.StatusOK)

	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"AKIAFULL"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::src/public*"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::src/private*"}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/src?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/src/public.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	privateGet := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/src/private.txt", nil, "AKIAFULL", "secret-full"), http.StatusForbidden)
	if !strings.Contains(privateGet.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for policy denied object, got %s", privateGet.Body.String())
	}

	missingAllow := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/src/other.txt", nil, "AKIAFULL", "secret-full"), http.StatusForbidden)
	if !strings.Contains(missingAllow.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for policy implicit deny, got %s", missingAllow.Body.String())
	}

	copyReq := signedReq(t, now, http.MethodPut, "http://localhost/dst/from-private.txt", nil, "AKIAFULL", "secret-full")
	copyReq.Header.Set("X-Amz-Copy-Source", "/src/private.txt")
	copyRes := mustRequest(t, h, copyReq, http.StatusForbidden)
	if !strings.Contains(copyRes.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for policy denied copy source read, got %s", copyRes.Body.String())
	}
}

func TestServiceBucketPolicyConditionAuthorizationAndProxySourceIP(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/secure-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/secure-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)

	secureTransportPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::secure-bucket/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/secure-bucket?policy", bytes.NewBufferString(secureTransportPolicy), "AKIAFULL", "secret-full"), http.StatusNoContent)

	insecureReq := signedReq(t, now, http.MethodGet, "http://localhost/secure-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	insecureRes := mustRequest(t, h, insecureReq, http.StatusForbidden)
	if !strings.Contains(insecureRes.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for insecure transport, got %s", insecureRes.Body.String())
	}

	secureReq := signedReq(t, now, http.MethodGet, "http://localhost/secure-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	secureReq.TLS = &tls.ConnectionState{}
	mustRequest(t, h, secureReq, http.StatusOK)

	sourceIPPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::secure-bucket/*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/secure-bucket?policy", bytes.NewBufferString(sourceIPPolicy), "AKIAFULL", "secret-full"), http.StatusNoContent)

	remoteDenied := signedReq(t, now, http.MethodGet, "http://localhost/secure-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	remoteDenied.RemoteAddr = "198.51.100.11:443"
	remoteDeniedRes := mustRequest(t, h, remoteDenied, http.StatusForbidden)
	if !strings.Contains(remoteDeniedRes.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for disallowed remote ip, got %s", remoteDeniedRes.Body.String())
	}

	remoteAllowed := signedReq(t, now, http.MethodGet, "http://localhost/secure-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	remoteAllowed.RemoteAddr = "203.0.113.44:443"
	mustRequest(t, h, remoteAllowed, http.StatusOK)

	svc.TrustProxyHeaders = true
	h = svc.Handler()
	proxyAllowed := signedReq(t, now, http.MethodGet, "http://localhost/secure-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	proxyAllowed.RemoteAddr = "198.51.100.10:443"
	proxyAllowed.Header.Set("X-Forwarded-For", "203.0.113.55")
	mustRequest(t, h, proxyAllowed, http.StatusOK)
}

func TestServiceBucketPolicyListPrefixCondition(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket/photos/one.jpg", bytes.NewBufferString("1"), "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket/videos/one.mp4", bytes.NewBufferString("1"), "AKIAFULL", "secret-full"), http.StatusOK)

	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::list-bucket","Condition":{"StringLike":{"s3:prefix":"photos/*"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/list-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	allowedList := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&prefix=photos/", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	if !strings.Contains(allowedList.Body.String(), "<Key>photos/one.jpg</Key>") {
		t.Fatalf("expected photos object in allowed prefix list response, got %s", allowedList.Body.String())
	}

	deniedList := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/list-bucket?list-type=2&prefix=videos/", nil, "AKIAFULL", "secret-full"), http.StatusForbidden)
	if !strings.Contains(deniedList.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for non-matching prefix, got %s", deniedList.Body.String())
	}
}

func TestServiceBucketPolicyPrincipalConditionKeys(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
  - name: "other"
    access_key: "AKIAOTHER"
    secret_key: "secret-other"
    allow:
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/principal-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/principal-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::principal-bucket/*","Condition":{"StringEquals":{"aws:userid":"AKIAFULL","aws:PrincipalType":"User"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/principal-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/principal-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	denied := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/principal-bucket/file.txt", nil, "AKIAOTHER", "secret-other"), http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for non-matching principal condition, got %s", denied.Body.String())
	}
}

func TestServiceBucketPolicyNumericMaxKeysCondition(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/numeric-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/numeric-bucket/a.txt", bytes.NewBufferString("a"), "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/numeric-bucket/b.txt", bytes.NewBufferString("b"), "AKIAFULL", "secret-full"), http.StatusOK)

	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::numeric-bucket","Condition":{"NumericLessThanEquals":{"s3:max-keys":"1"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/numeric-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/numeric-bucket?list-type=2&max-keys=1", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	denied := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/numeric-bucket?list-type=2&max-keys=2", nil, "AKIAFULL", "secret-full"), http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for non-matching numeric max-keys policy, got %s", denied.Body.String())
	}
}

func TestServiceBucketPolicyDateCurrentTimeCondition(t *testing.T) {
	t.Parallel()
	nowValue := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return nowValue },
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, nowValue, http.MethodPut, "http://localhost/date-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, nowValue, http.MethodPut, "http://localhost/date-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::date-bucket/*","Condition":{"DateLessThan":{"aws:CurrentTime":"2026-02-14T12:05:00Z"}}}]}`
	mustRequest(t, h, signedReq(t, nowValue, http.MethodPut, "http://localhost/date-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, nowValue, http.MethodGet, "http://localhost/date-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	nowValue = time.Date(2026, 2, 14, 12, 10, 0, 0, time.UTC)
	denied := mustRequest(t, h, signedReq(t, time.Date(2026, 2, 14, 12, 2, 0, 0, time.UTC), http.MethodGet, "http://localhost/date-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for current-time date condition failure, got %s", denied.Body.String())
	}
}

func TestPolicyAttributesFromRequestIncludesSignatureAge(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket?list-type=2", nil)
	req.Header.Set("X-Amz-Date", "20260214T120000Z")
	now := time.Date(2026, 2, 14, 12, 0, 5, 0, time.UTC)

	attrs := policyAttributesFromRequest(req, s3.OperationListObjects, authz.Principal{AccessKey: "AKIAFULL", Name: "full"}, net.ParseIP("203.0.113.44"), now)
	if got := attrs["s3:signatureAge"]; got != "5000" {
		t.Fatalf("expected s3:signatureAge=5000, got %q", got)
	}
	if got := attrs["aws:CurrentTime"]; got != "2026-02-14T12:00:05Z" {
		t.Fatalf("expected aws:CurrentTime value, got %q", got)
	}
	if got := attrs["aws:PrincipalAccount"]; got != "local" {
		t.Fatalf("expected aws:PrincipalAccount=local, got %q", got)
	}
	if got := attrs["s3:authType"]; got != "REST-HEADER" {
		t.Fatalf("expected s3:authType=REST-HEADER, got %q", got)
	}
	if got := attrs["s3:signatureversion"]; got != "AWS4-HMAC-SHA256" {
		t.Fatalf("expected s3:signatureversion=AWS4-HMAC-SHA256, got %q", got)
	}
}

func TestPolicyPrincipalCandidatesIncludesKeyNameAndARN(t *testing.T) {
	t.Parallel()
	candidates := policyPrincipalCandidates(
		authz.Principal{AccessKey: "AKIAFULL", Name: "full"},
		policy.EvaluationContext{
			Attributes: map[string]string{
				"aws:userid":       "AKIAFULL",
				"aws:username":     "full",
				"aws:PrincipalArn": "arn:storas:iam::local:user/full",
			},
		},
	)
	joined := strings.Join(candidates, ",")
	if !strings.Contains(joined, "AKIAFULL") {
		t.Fatalf("expected access-key candidate, got %v", candidates)
	}
	if !strings.Contains(joined, "full") {
		t.Fatalf("expected username candidate, got %v", candidates)
	}
	if !strings.Contains(joined, "arn:storas:iam::local:user/full") {
		t.Fatalf("expected principal arn candidate, got %v", candidates)
	}
}

func TestServiceBucketPolicyNotPrincipal(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "bucket:delete"
        resource: "*"
  - name: "other"
    access_key: "AKIAOTHER"
    secret_key: "secret-other"
    allow:
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()

	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/notprincipal-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/notprincipal-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::notprincipal-bucket/*"},{"Effect":"Deny","NotPrincipal":{"AWS":"AKIAFULL"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::notprincipal-bucket/*"}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/notprincipal-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/notprincipal-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)

	denied := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/notprincipal-bucket/file.txt", nil, "AKIAOTHER", "secret-other"), http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for NotPrincipal non-match, got %s", denied.Body.String())
	}
}

func TestServiceBucketPolicyStringEqualsIfExistsVersionID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ifexists-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ifexists-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::ifexists-bucket/*","Condition":{"StringEqualsIfExists":{"s3:VersionId":"v1"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/ifexists-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/ifexists-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	denied := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/ifexists-bucket/file.txt?versionId=bad", nil, "AKIAFULL", "secret-full"), http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for non-matching versionId IfExists condition, got %s", denied.Body.String())
	}
}

func TestServiceBucketPolicyForAnyValueRequestHeaderCondition(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/header-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/header-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::header-bucket/*","Condition":{"ForAnyValue:StringEquals":{"s3:RequestHeader/X-Role":["prod","ops"]}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/header-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	allowedReq := signedReq(t, now, http.MethodGet, "http://localhost/header-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	allowedReq.Header.Add("X-Role", "dev")
	allowedReq.Header.Add("X-Role", "prod")
	mustRequest(t, h, allowedReq, http.StatusOK)

	deniedReq := signedReq(t, now, http.MethodGet, "http://localhost/header-bucket/file.txt", nil, "AKIAFULL", "secret-full")
	deniedReq.Header.Add("X-Role", "dev")
	denied := mustRequest(t, h, deniedReq, http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for ForAnyValue header mismatch, got %s", denied.Body.String())
	}
}

func TestServiceBucketPolicyArnConditionKeys(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	backend, engine := testBackendAndEngine(t, `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
  - name: "other"
    access_key: "AKIAOTHER"
    secret_key: "secret-other"
    allow:
      - action: "object:get"
        resource: "*/*"
`)
	svc := &Service{
		Backend:     backend,
		Authz:       engine,
		Region:      "us-west-1",
		ServiceName: "s3",
		ClockSkew:   15 * time.Minute,
		Now:         func() time.Time { return now },
	}
	h := svc.Handler()
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/arn-bucket", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/arn-bucket/file.txt", bytes.NewBufferString("ok"), "AKIAFULL", "secret-full"), http.StatusOK)
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::arn-bucket/*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:storas:iam::local:user/full"}}},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::arn-bucket/*","Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:storas:iam::local:user/other"}}}]}`
	mustRequest(t, h, signedReq(t, now, http.MethodPut, "http://localhost/arn-bucket?policy", bytes.NewBufferString(policyDoc), "AKIAFULL", "secret-full"), http.StatusNoContent)

	mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/arn-bucket/file.txt", nil, "AKIAFULL", "secret-full"), http.StatusOK)
	denied := mustRequest(t, h, signedReq(t, now, http.MethodGet, "http://localhost/arn-bucket/file.txt", nil, "AKIAOTHER", "secret-other"), http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for arn condition mismatch/deny, got %s", denied.Body.String())
	}
}

func TestResolveSourceIPPrefersProxyHeadersOnlyWhenTrusted(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "198.51.100.9:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.77, 10.0.0.1")
	ip := resolveSourceIP(req, false)
	if got := sourceIPString(ip); got != "198.51.100.9" {
		t.Fatalf("expected remote addr ip when proxy headers untrusted, got %q", got)
	}
	ip = resolveSourceIP(req, true)
	if got := sourceIPString(ip); got != "203.0.113.77" {
		t.Fatalf("expected forwarded ip when proxy headers trusted, got %q", got)
	}
}

func testBackendAndEngine(t *testing.T, authYAML string) (*storage.FSBackend, *authz.Engine) {
	t.Helper()
	return testBackendAndEngineWithLimit(t, authYAML, 25*1024*1024*1024)
}

func testBackendAndEngineWithLimit(t *testing.T, authYAML string, maxObjectSize int64) (*storage.FSBackend, *authz.Engine) {
	t.Helper()
	dir := t.TempDir()
	backend, err := storage.NewFSBackend(filepath.Join(dir, "data"), maxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	authPath := filepath.Join(dir, "authorization.yaml")
	if err := os.WriteFile(authPath, []byte(authYAML), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	engine, err := authz.LoadFile(authPath)
	if err != nil {
		t.Fatalf("LoadFile authz error: %v", err)
	}
	return backend, engine
}

func signedReq(t *testing.T, now time.Time, method, rawURL string, body io.Reader, accessKey, secret string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, rawURL, body)
	signRequest(t, req, now, accessKey, secret, "us-west-1", "s3")
	return req
}

func signRequest(t *testing.T, req *http.Request, now time.Time, accessKey, secret, region, service string) {
	t.Helper()
	signRequestWithPayloadHash(t, req, now, accessKey, secret, region, service, "UNSIGNED-PAYLOAD")
}

func signedReqWithPayloadHash(t *testing.T, now time.Time, method, rawURL string, body io.Reader, accessKey, secret, payloadHash string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, rawURL, body)
	signRequestWithPayloadHash(t, req, now, accessKey, secret, "us-west-1", "s3", payloadHash)
	return req
}

func signRequestWithPayloadHash(t *testing.T, req *http.Request, now time.Time, accessKey, secret, region, service, payloadHash string) {
	t.Helper()
	req.Header.Set("X-Amz-Date", now.UTC().Format(sigv4.DateFormat))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}

	canonical, err := sigv4.BuildCanonicalRequest(req, signedHeaders, payloadHash)
	if err != nil {
		t.Fatalf("BuildCanonicalRequest: %v", err)
	}
	scope := sigv4.CredentialScope{AccessKey: accessKey, Date: now.UTC().Format("20060102"), Region: region, Service: service, Terminal: "aws4_request"}
	stringToSign := sigv4.BuildStringToSign(canonical, now.UTC(), scope)
	sig := sigv4.SignatureHex(sigv4.SigningKey(secret, scope.Date, scope.Region, scope.Service), stringToSign)

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+scope.AccessKey+"/"+scope.Date+"/"+scope.Region+"/"+scope.Service+"/"+scope.Terminal+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+sig)
}

func buildStreamingPayloadForRequest(t *testing.T, req *http.Request, secret string, chunks []string) string {
	t.Helper()
	auth, err := sigv4.ParseAuthorizationHeader(req.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("ParseAuthorizationHeader: %v", err)
	}
	signingKey := sigv4.SigningKey(secret, auth.Credential.Date, auth.Credential.Region, auth.Credential.Service)
	scope := fmt.Sprintf("%s/%s/%s/%s", auth.Credential.Date, auth.Credential.Region, auth.Credential.Service, auth.Credential.Terminal)
	requestDate := req.Header.Get("X-Amz-Date")
	prev := auth.Signature
	var out strings.Builder

	for _, chunk := range chunks {
		data := []byte(chunk)
		chunkSig := sigv4.SignatureHex(signingKey, strings.Join([]string{
			"AWS4-HMAC-SHA256-PAYLOAD",
			requestDate,
			scope,
			prev,
			sha256Hex(nil),
			sha256Hex(data),
		}, "\n"))
		_, _ = fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n", len(data), chunkSig)
		out.Write(data)
		out.WriteString("\r\n")
		prev = chunkSig
	}

	finalSig := sigv4.SignatureHex(signingKey, strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		requestDate,
		scope,
		prev,
		sha256Hex(nil),
		sha256Hex(nil),
	}, "\n"))
	_, _ = fmt.Fprintf(&out, "0;chunk-signature=%s\r\n\r\n", finalSig)
	return out.String()
}

func sha256Hex(v []byte) string {
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:])
}

func mustRequest(t *testing.T, handler http.Handler, req *http.Request, wantCode int) *httptest.ResponseRecorder {
	t.Helper()
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != wantCode {
		t.Fatalf("unexpected status=%d want=%d body=%s", res.Code, wantCode, res.Body.String())
	}
	return res
}
