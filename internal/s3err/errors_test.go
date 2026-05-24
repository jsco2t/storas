package s3err

import (
	"context"
	"encoding/xml"
	"fmt"
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

func TestMapErrorNilInputReturnsZeroValue(t *testing.T) {
	t.Parallel()
	got := MapError(nil)
	if got.Code != "" || got.Message != "" || got.StatusCode != 0 {
		t.Fatalf("expected zero-value APIError for nil input, got: %+v", got)
	}
}

func TestMapErrorCanceledReturnsRequestTimeout(t *testing.T) {
	t.Parallel()
	got := MapError(context.Canceled)
	if got.StatusCode != 400 {
		t.Fatalf("expected 400 for context.Canceled, got status %d", got.StatusCode)
	}
	if got.Code != "RequestTimeout" {
		t.Fatalf("expected RequestTimeout code for context.Canceled, got %q", got.Code)
	}
	if got.Message == "" {
		t.Fatalf("expected descriptive RequestTimeout message, got empty")
	}
}

func TestMapErrorDeadlineExceededReturnsServiceUnavailable(t *testing.T) {
	t.Parallel()
	got := MapError(context.DeadlineExceeded)
	if got.StatusCode != 503 {
		t.Fatalf("expected 503 for context.DeadlineExceeded, got status %d", got.StatusCode)
	}
	if got.Code != "InternalError" {
		t.Fatalf("expected InternalError code for context.DeadlineExceeded, got %q", got.Code)
	}
	if got.Message == "" {
		t.Fatalf("expected descriptive ServiceUnavailable message, got empty")
	}
}

func TestMapErrorWrappedCanceledReturnsRequestTimeout(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("backend read: %w", context.Canceled)
	got := MapError(wrapped)
	if got.Code != "RequestTimeout" || got.StatusCode != 400 {
		t.Fatalf("expected wrapped context.Canceled to map to RequestTimeout/400, got %+v", got)
	}
}

func TestMapErrorWrappedDeadlineExceededReturnsServiceUnavailable(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("backend read: %w", context.DeadlineExceeded)
	got := MapError(wrapped)
	if got.Code != "InternalError" || got.StatusCode != 503 {
		t.Fatalf("expected wrapped context.DeadlineExceeded to map to InternalError/503, got %+v", got)
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
	if got := MapError(context.Canceled); got.Code != "RequestTimeout" || got.StatusCode != 400 {
		t.Fatalf("unexpected mapping for context.Canceled: %+v", got)
	}
	if got := MapError(context.DeadlineExceeded); got.Code != "InternalError" || got.StatusCode != 503 {
		t.Fatalf("unexpected mapping for context.DeadlineExceeded: %+v", got)
	}
	if got := MapError(sigv4.ErrUnsupportedPayloadMode); got.Code != "InvalidRequest" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
}
