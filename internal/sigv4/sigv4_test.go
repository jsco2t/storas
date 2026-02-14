package sigv4

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseAuthorizationHeader(t *testing.T) {
	t.Parallel()
	header := "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260213/us-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef"
	auth, err := ParseAuthorizationHeader(header)
	if err != nil {
		t.Fatalf("ParseAuthorizationHeader error: %v", err)
	}
	if auth.Credential.AccessKey != "AKIAEXAMPLE" || len(auth.SignedHeaders) != 2 {
		t.Fatalf("unexpected auth parse: %+v", auth)
	}
}

func TestParseRequestAuthPresign(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	r := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE%2F20260213%2Fus-west-1%2Fs3%2Faws4_request&X-Amz-Date=20260213T100000Z&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef", nil)
	auth, err := ParseRequestAuth(r, now, 15*time.Minute)
	if err != nil {
		t.Fatalf("ParseRequestAuth presign error: %v", err)
	}
	if auth.Mode != AuthModePresign {
		t.Fatalf("expected presign mode, got %s", auth.Mode)
	}
}

func TestParseAmzDateSkew(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	_, err := ParseAmzDate("20260213T080000Z", now, 15*time.Minute)
	if err == nil {
		t.Fatal("expected skew error")
	}
}

func TestBuildCanonicalRequest(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key?list-type=2&prefix=a", nil)
	r.Header.Set("X-Amz-Date", "20260213T100000Z")
	canonical, err := BuildCanonicalRequest(r, []string{"host", "x-amz-date"}, "UNSIGNED-PAYLOAD")
	if err != nil {
		t.Fatalf("BuildCanonicalRequest error: %v", err)
	}
	if !strings.Contains(canonical, "host:localhost") {
		t.Fatalf("canonical request missing host header: %s", canonical)
	}
	if !strings.Contains(canonical, "list-type=2&prefix=a") {
		t.Fatalf("canonical request missing canonical query: %s", canonical)
	}
}

func TestBuildCanonicalRequestEncodesPathAndQueryPerS3Rules(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/file%20name.txt?prefix=a%20b", nil)
	r.URL.Path = "/bucket/dir/file name.txt"
	r.URL.RawPath = "/bucket/dir%2Ffile%20name.txt"
	r.Header.Set("X-Amz-Date", "20260213T100000Z")
	canonical, err := BuildCanonicalRequest(r, []string{"host", "x-amz-date"}, "UNSIGNED-PAYLOAD")
	if err != nil {
		t.Fatalf("BuildCanonicalRequest error: %v", err)
	}
	if !strings.Contains(canonical, "/bucket/dir%2Ffile%20name.txt") {
		t.Fatalf("canonical request missing encoded URI semantics: %s", canonical)
	}
	if !strings.Contains(canonical, "prefix=a%20b") {
		t.Fatalf("canonical request missing %%20 query encoding: %s", canonical)
	}
}

func TestBuildCanonicalRequestCanonicalizesDuplicateSignedHeaderValues(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	r.Header.Add("X-Amz-Meta-Test", " value-one ")
	r.Header.Add("X-Amz-Meta-Test", "value-two")
	canonical, err := BuildCanonicalRequest(r, []string{"host", "x-amz-meta-test"}, "UNSIGNED-PAYLOAD")
	if err != nil {
		t.Fatalf("BuildCanonicalRequest error: %v", err)
	}
	if !strings.Contains(canonical, "x-amz-meta-test:value-one,value-two") {
		t.Fatalf("expected canonicalized duplicate header values, got: %s", canonical)
	}
}

func TestParseRequestAuthAcceptsStreamingPayloadMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	r := httptest.NewRequest(http.MethodPut, "http://localhost/bucket/key", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260213/us-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date;x-amz-content-sha256, Signature=abcdef")
	r.Header.Set("X-Amz-Date", "20260213T100000Z")
	r.Header.Set("X-Amz-Content-Sha256", StreamingPayload)
	auth, err := ParseRequestAuth(r, now, 15*time.Minute)
	if err != nil {
		t.Fatalf("expected streaming payload mode to parse, got %v", err)
	}
	if auth.PayloadHash != StreamingPayload {
		t.Fatalf("expected streaming payload hash, got %q", auth.PayloadHash)
	}
}
