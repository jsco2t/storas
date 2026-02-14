package sigv4

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyRequestSuccess(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	secret := "test-secret"
	r := httptest.NewRequest(http.MethodGet, "http://localhost/test-bucket/file.txt", nil)
	r.Header.Set("X-Amz-Date", now.Format(DateFormat))
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonical, err := BuildCanonicalRequest(r, signedHeaders, "UNSIGNED-PAYLOAD")
	if err != nil {
		t.Fatalf("BuildCanonicalRequest error: %v", err)
	}
	scope := CredentialScope{AccessKey: "AKIAEXAMPLE", Date: now.Format("20060102"), Region: "us-west-1", Service: "s3", Terminal: "aws4_request"}
	stringToSign := BuildStringToSign(canonical, now, scope)
	sig := SignatureHex(SigningKey(secret, scope.Date, scope.Region, scope.Service), stringToSign)

	auth := RequestAuth{Authorization: Authorization{Credential: scope, SignedHeaders: signedHeaders, Signature: sig}, RequestTime: now, SignedHeaders: signedHeaders, PayloadHash: "UNSIGNED-PAYLOAD"}
	if err := VerifyRequest(r, auth, secret, "us-west-1", "s3"); err != nil {
		t.Fatalf("VerifyRequest error: %v", err)
	}
}

func TestValidateScopeFailure(t *testing.T) {
	t.Parallel()
	err := ValidateScope(CredentialScope{Region: "us-east-1", Service: "s3", Terminal: "aws4_request"}, "us-west-1", "s3")
	if err == nil {
		t.Fatal("expected scope validation error")
	}
}

func TestVerifySignatureConstantTimeCompare(t *testing.T) {
	t.Parallel()
	if !VerifySignature("abcdef", "abcdef") {
		t.Fatal("expected identical signatures to match")
	}
	if VerifySignature("abcdef", "abcdeg") {
		t.Fatal("expected different signatures to fail")
	}
}
