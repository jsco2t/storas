package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestFSBackendMultipartLifecycle(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "multi-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	uploadID, err := backend.CreateMultipartUpload(context.Background(), "multi-bucket", "obj.txt", ObjectMetadata{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	if uploadID == "" {
		t.Fatal("expected upload ID")
	}

	part1, err := backend.UploadPart(context.Background(), "multi-bucket", "obj.txt", uploadID, 1, bytes.NewBufferString("hello "))
	if err != nil {
		t.Fatalf("UploadPart1 error: %v", err)
	}
	part2, err := backend.UploadPart(context.Background(), "multi-bucket", "obj.txt", uploadID, 2, bytes.NewBufferString("world"))
	if err != nil {
		t.Fatalf("UploadPart2 error: %v", err)
	}

	parts, err := backend.ListParts(context.Background(), "multi-bucket", "obj.txt", uploadID, ListPartsOptions{})
	if err != nil {
		t.Fatalf("ListParts error: %v", err)
	}
	if len(parts.Parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts.Parts))
	}

	obj, err := backend.CompleteMultipartUpload(context.Background(), "multi-bucket", "obj.txt", uploadID, []CompletedPart{{PartNumber: 1, ETag: part1.ETag}, {PartNumber: 2, ETag: part2.ETag}})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload error: %v", err)
	}
	if obj.Size != int64(len("hello world")) {
		t.Fatalf("unexpected object size: %d", obj.Size)
	}

	rc, _, err := backend.GetObject(context.Background(), "multi-bucket", "obj.txt")
	if err != nil {
		t.Fatalf("GetObject error: %v", err)
	}
	defer rc.Close()
	payload, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(payload) != "hello world" {
		t.Fatalf("unexpected payload: %q", string(payload))
	}
}

func TestFSBackendAbortMultipartUpload(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "abort-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	uploadID, err := backend.CreateMultipartUpload(context.Background(), "abort-bucket", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	if _, err := backend.UploadPart(context.Background(), "abort-bucket", "obj.txt", uploadID, 1, bytes.NewBufferString("value")); err != nil {
		t.Fatalf("UploadPart error: %v", err)
	}
	if err := backend.AbortMultipartUpload(context.Background(), "abort-bucket", "obj.txt", uploadID); err != nil {
		t.Fatalf("AbortMultipartUpload error: %v", err)
	}
	if _, err := backend.ListParts(context.Background(), "abort-bucket", "obj.txt", uploadID, ListPartsOptions{}); err == nil {
		t.Fatal("expected no such upload after abort")
	}
}

func TestFSBackendCompleteMultipartUploadValidatesPartOrdering(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "order-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	uploadID, err := backend.CreateMultipartUpload(context.Background(), "order-bucket", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	part1, err := backend.UploadPart(context.Background(), "order-bucket", "obj.txt", uploadID, 1, bytes.NewBuffer(make([]byte, 5*1024*1024)))
	if err != nil {
		t.Fatalf("UploadPart 1 error: %v", err)
	}
	part2, err := backend.UploadPart(context.Background(), "order-bucket", "obj.txt", uploadID, 2, bytes.NewBufferString("tail"))
	if err != nil {
		t.Fatalf("UploadPart 2 error: %v", err)
	}

	_, err = backend.CompleteMultipartUpload(context.Background(), "order-bucket", "obj.txt", uploadID, []CompletedPart{
		{PartNumber: 2, ETag: part2.ETag},
		{PartNumber: 1, ETag: part1.ETag},
	})
	if !errors.Is(err, ErrInvalidPartOrder) {
		t.Fatalf("expected ErrInvalidPartOrder, got %v", err)
	}
}

func TestFSBackendUploadPartValidatesInput(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "validate-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	uploadID, err := backend.CreateMultipartUpload(context.Background(), "validate-bucket", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	if _, err := backend.UploadPart(context.Background(), "validate-bucket", "obj.txt", uploadID, maxMultipartPartNumber+1, bytes.NewBufferString("value")); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("expected ErrInvalidPart for part number >10000, got %v", err)
	}
	if _, err := backend.UploadPart(context.Background(), "validate-bucket", "obj.txt", "../bad", 1, bytes.NewBufferString("value")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for invalid upload ID, got %v", err)
	}
}

func TestFSBackendListMultipartUploadsMarkerSemantics(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "marker-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	if _, err := backend.CreateMultipartUpload(context.Background(), "marker-bucket", "b.txt", ObjectMetadata{}); err != nil {
		t.Fatalf("CreateMultipartUpload b.txt error: %v", err)
	}
	if _, err := backend.CreateMultipartUpload(context.Background(), "marker-bucket", "a.txt", ObjectMetadata{}); err != nil {
		t.Fatalf("CreateMultipartUpload a.txt #1 error: %v", err)
	}
	if _, err := backend.CreateMultipartUpload(context.Background(), "marker-bucket", "a.txt", ObjectMetadata{}); err != nil {
		t.Fatalf("CreateMultipartUpload a.txt #2 error: %v", err)
	}

	all, err := backend.ListMultipartUploads(context.Background(), "marker-bucket", MultipartUploadListOptions{MaxUploads: 1000})
	if err != nil {
		t.Fatalf("ListMultipartUploads all error: %v", err)
	}
	if len(all.Uploads) != 3 {
		t.Fatalf("expected 3 uploads, got %d", len(all.Uploads))
	}

	afterKeyOnly, err := backend.ListMultipartUploads(context.Background(), "marker-bucket", MultipartUploadListOptions{
		KeyMarker:  "a.txt",
		MaxUploads: 1000,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads key-marker error: %v", err)
	}
	if len(afterKeyOnly.Uploads) != 1 || afterKeyOnly.Uploads[0].Key != "b.txt" {
		t.Fatalf("expected key-marker without upload-id-marker to skip all a.txt uploads, got %+v", afterKeyOnly.Uploads)
	}

	aUploads := make([]string, 0, 2)
	for _, up := range all.Uploads {
		if up.Key == "a.txt" {
			aUploads = append(aUploads, up.UploadID)
		}
	}
	if len(aUploads) != 2 {
		t.Fatalf("expected 2 a.txt uploads, got %d", len(aUploads))
	}
	sort.Strings(aUploads)

	afterKeyAndUpload, err := backend.ListMultipartUploads(context.Background(), "marker-bucket", MultipartUploadListOptions{
		KeyMarker:         "a.txt",
		UploadIDMarker:    aUploads[0],
		HasUploadIDMarker: true,
		MaxUploads:        1000,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads key+upload marker error: %v", err)
	}
	if len(afterKeyAndUpload.Uploads) == 0 || afterKeyAndUpload.Uploads[0].Key != "a.txt" || afterKeyAndUpload.Uploads[0].UploadID != aUploads[1] {
		t.Fatalf("expected first upload after key/upload marker to be second a.txt upload, got %+v", afterKeyAndUpload.Uploads)
	}
}

func TestFSBackendMultipartOpsHonorCanceledContext(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "cancel-multipart"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	uploadID, err := backend.CreateMultipartUpload(context.Background(), "cancel-multipart", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	if _, err := backend.UploadPart(context.Background(), "cancel-multipart", "obj.txt", uploadID, 1, bytes.NewBufferString("hello")); err != nil {
		t.Fatalf("UploadPart setup error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := backend.ListMultipartUploads(ctx, "cancel-multipart", MultipartUploadListOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from ListMultipartUploads, got %v", err)
	}
	if _, err := backend.ListParts(ctx, "cancel-multipart", "obj.txt", uploadID, ListPartsOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from ListParts, got %v", err)
	}
	if _, err := backend.CompleteMultipartUpload(ctx, "cancel-multipart", "obj.txt", uploadID, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from CompleteMultipartUpload, got %v", err)
	}
	if err := backend.AbortMultipartUpload(ctx, "cancel-multipart", "obj.txt", uploadID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from AbortMultipartUpload, got %v", err)
	}
}

func TestGenerateMultipartUploadIDUniquenessAndFormat(t *testing.T) {
	t.Parallel()
	const samples = 1024
	seen := make(map[string]struct{}, samples)
	numericOnly := regexp.MustCompile(`^up-[0-9-]+$`)
	for i := 0; i < samples; i++ {
		uploadID, err := generateMultipartUploadID()
		if err != nil {
			t.Fatalf("generateMultipartUploadID error: %v", err)
		}
		if !multipartUploadIDPattern.MatchString(uploadID) {
			t.Fatalf("upload id %q does not match required pattern", uploadID)
		}
		if numericOnly.MatchString(uploadID) {
			t.Fatalf("upload id %q appears timestamp-only", uploadID)
		}
		if !strings.HasPrefix(uploadID, "up-") {
			t.Fatalf("upload id %q missing prefix", uploadID)
		}
		if _, ok := seen[uploadID]; ok {
			t.Fatalf("duplicate upload id generated: %s", uploadID)
		}
		seen[uploadID] = struct{}{}
	}
}

func TestCreateMultipartUploadIDsRemainUniqueUnderConcurrency(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "multipart-id-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	const (
		workers    = 12
		iterations = 40
	)
	seen := make(map[string]struct{}, workers*iterations)
	var seenMu sync.Mutex

	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				uploadID, createErr := backend.CreateMultipartUpload(ctx, "multipart-id-bucket", fmt.Sprintf("obj-%02d.txt", i%4), ObjectMetadata{})
				if createErr != nil {
					errCh <- createErr
					return
				}
				seenMu.Lock()
				if _, ok := seen[uploadID]; ok {
					seenMu.Unlock()
					errCh <- fmt.Errorf("duplicate upload id: %s", uploadID)
					return
				}
				seen[uploadID] = struct{}{}
				seenMu.Unlock()
			}
		}(w)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for runErr := range errCh {
		if runErr != nil {
			t.Fatalf("concurrent upload-id test failed: %v", runErr)
		}
	}

	if len(seen) != workers*iterations {
		t.Fatalf("expected %d unique ids, got %d", workers*iterations, len(seen))
	}
}
