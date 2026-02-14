package s3err

import (
	"context"
	"encoding/xml"
	"net/http/httptest"
	"strings"
	"testing"

	"storas/internal/sigv4"
	"storas/internal/storage"
)

func TestWriteProducesS3ErrorXML(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	Write(w, "req-123", AccessDenied, "bucket/key")
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/xml") {
		t.Fatalf("unexpected content type: %s", ct)
	}

	var parsed struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource"`
		RequestID string   `xml:"RequestId"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal XML error: %v", err)
	}
	if parsed.Code != "AccessDenied" || parsed.RequestID != "req-123" {
		t.Fatalf("unexpected error body: %+v", parsed)
	}
}

func TestMapErrorCanonicalMappings(t *testing.T) {
	t.Parallel()
	if got := MapError(AccessDenied); got.Code != "AccessDenied" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrNoSuchBucket); got.Code != "NoSuchBucket" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrNoSuchBucketPolicy); got.Code != "NoSuchBucketPolicy" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrEntityTooLarge); got.Code != "EntityTooLarge" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrNoSuchUpload); got.Code != "NoSuchUpload" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrNoSuchVersion); got.Code != "NoSuchVersion" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrNoSuchLifecycleConfiguration); got.Code != "NoSuchLifecycleConfiguration" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrInvalidPart); got.Code != "InvalidPart" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrInvalidPartOrder); got.Code != "InvalidPartOrder" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrInvalidRequest); got.Code != "InvalidRequest" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrInvalidVersionID); got.Code != "InvalidRequest" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(storage.ErrBadDigest); got.Code != "BadDigest" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(context.Canceled); got.Code != "RequestTimeout" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(context.DeadlineExceeded); got.Code != "RequestTimeout" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got := MapError(sigv4.ErrUnsupportedPayloadMode); got.Code != "InvalidRequest" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
}
