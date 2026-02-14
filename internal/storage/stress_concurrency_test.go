//go:build stress

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStressStorageHighContentionVersionAndMetadataInvariants(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "stress-storage"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketVersioning(ctx, "stress-storage", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning error: %v", err)
	}

	const (
		workers    = 12
		iterations = 80
	)
	workloadDuration := parseStressWorkloadDuration(t)
	workloadDeadline := time.Now().Add(workloadDuration)

	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(1000 + worker)))
			<-start
			for i := 0; ; i++ {
				if workloadDuration > 0 {
					if time.Now().After(workloadDeadline) {
						break
					}
				} else if i >= iterations {
					break
				}
				key := fmt.Sprintf("obj-%02d.txt", rng.Intn(6))
				switch rng.Intn(5) {
				case 0:
					payload := []byte(fmt.Sprintf("w=%d i=%d", worker, i))
					if _, putErr := backend.PutObject(ctx, "stress-storage", key, bytes.NewReader(payload), ObjectMetadata{ContentType: "text/plain", UserMetadata: map[string]string{"worker": fmt.Sprintf("%d", worker)}}); putErr != nil {
						errCh <- putErr
						return
					}
				case 1:
					rc, _, getErr := backend.GetObject(ctx, "stress-storage", key)
					if getErr != nil {
						if errors.Is(getErr, ErrNoSuchKey) {
							continue
						}
						errCh <- getErr
						return
					}
					_, _ = io.Copy(io.Discard, rc)
					_ = rc.Close()
				case 2:
					if _, headErr := backend.HeadObject(ctx, "stress-storage", key); headErr != nil && !errors.Is(headErr, ErrNoSuchKey) {
						errCh <- headErr
						return
					}
				case 3:
					if _, delErr := backend.DeleteObjectVersion(ctx, "stress-storage", key, ""); delErr != nil {
						errCh <- delErr
						return
					}
				default:
					if _, listErr := backend.ListObjectsV2(ctx, "stress-storage", ListObjectsOptions{MaxKeys: 5, Prefix: "obj-"}); listErr != nil {
						errCh <- listErr
						return
					}
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for runErr := range errCh {
		if runErr != nil {
			t.Fatalf("stress worker error: %v", runErr)
		}
	}

	page, listErr := backend.ListObjectVersions(ctx, "stress-storage", ListObjectVersionsOptions{MaxKeys: 1000})
	if listErr != nil {
		t.Fatalf("ListObjectVersions error: %v", listErr)
	}
	for _, version := range page.Versions {
		if strings.TrimSpace(version.VersionID) == "" {
			t.Fatalf("empty version id for key %s", version.Key)
		}
		if version.IsDeleteMark {
			continue
		}
		rc, meta, getErr := backend.GetObjectVersion(ctx, "stress-storage", version.Key, version.VersionID)
		if getErr != nil {
			t.Fatalf("GetObjectVersion %s/%s failed: %v", version.Key, version.VersionID, getErr)
		}
		data, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatalf("read version payload %s/%s failed: %v", version.Key, version.VersionID, readErr)
		}
		if int64(len(data)) != meta.ContentLength {
			t.Fatalf("content-length mismatch for %s/%s: meta=%d actual=%d", version.Key, version.VersionID, meta.ContentLength, len(data))
		}
	}
}

func parseStressWorkloadDuration(t *testing.T) time.Duration {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("STRESS_WORKLOAD_DURATION"))
	if raw == "" {
		return 0
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		t.Fatalf("invalid STRESS_WORKLOAD_DURATION %q: %v", raw, err)
	}
	if duration <= 0 {
		t.Fatalf("invalid STRESS_WORKLOAD_DURATION %q: must be > 0", raw)
	}
	return duration
}

func TestStressStorageMultipartCleanupAndListPagination(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "stress-multipart"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	for i := 0; i < 20; i++ {
		up, createErr := backend.CreateMultipartUpload(ctx, "stress-multipart", fmt.Sprintf("k/%02d.txt", i), ObjectMetadata{})
		if createErr != nil {
			t.Fatalf("CreateMultipartUpload error: %v", createErr)
		}
		if _, uploadErr := backend.UploadPart(ctx, "stress-multipart", fmt.Sprintf("k/%02d.txt", i), up, 1, bytes.NewBufferString("payload")); uploadErr != nil {
			t.Fatalf("UploadPart error: %v", uploadErr)
		}
	}

	seen := map[string]struct{}{}
	opts := MultipartUploadListOptions{Prefix: "k/", MaxUploads: 3}
	for {
		page, listErr := backend.ListMultipartUploads(ctx, "stress-multipart", opts)
		if listErr != nil {
			t.Fatalf("ListMultipartUploads error: %v", listErr)
		}
		for _, up := range page.Uploads {
			id := up.Key + "#" + up.UploadID
			if _, ok := seen[id]; ok {
				t.Fatalf("duplicate upload encountered across pages: %s", id)
			}
			seen[id] = struct{}{}
		}
		if !page.IsTruncated {
			break
		}
		opts.KeyMarker = page.NextKeyMarker
		opts.UploadIDMarker = page.NextUploadIDMarker
		opts.HasUploadIDMarker = true
	}
	if len(seen) != 20 {
		t.Fatalf("expected to see 20 uploads, got %d", len(seen))
	}

	if _, sweepErr := backend.SweepStaleMultipartUploads(ctx, time.Now().UTC().Add(2*time.Hour), MultipartSweepOptions{StaleAfter: time.Hour, MaxRemovals: 100}); sweepErr != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", sweepErr)
	}
	after, err := backend.ListMultipartUploads(ctx, "stress-multipart", MultipartUploadListOptions{MaxUploads: 1000})
	if err != nil {
		t.Fatalf("ListMultipartUploads after sweep error: %v", err)
	}
	if len(after.Uploads) != 0 {
		t.Fatalf("expected multipart uploads to be cleaned, got %d", len(after.Uploads))
	}
}
