package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func markUploadTreeOld(t *testing.T, uploadDir string, ts time.Time) {
	t.Helper()
	if err := filepath.WalkDir(uploadDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if chErr := os.Chtimes(path, ts, ts); chErr != nil {
			return chErr
		}
		return nil
	}); err != nil {
		t.Fatalf("mark upload tree old: %v", err)
	}
	if err := os.Chtimes(uploadDir, ts, ts); err != nil {
		t.Fatalf("chtimes upload dir: %v", err)
	}
}

func TestSweepStaleMultipartUploadsRemovesStaleUploads(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "stale-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	oldID, err := backend.CreateMultipartUpload(context.Background(), "stale-bucket", "old.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload old error: %v", err)
	}
	freshID, err := backend.CreateMultipartUpload(context.Background(), "stale-bucket", "fresh.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload fresh error: %v", err)
	}

	oldManifestPath := backend.multipartManifestPath("stale-bucket", oldID)
	oldManifest, err := backend.readMultipartManifest(context.Background(), "stale-bucket", oldID)
	if err != nil {
		t.Fatalf("read old manifest: %v", err)
	}
	oldManifest.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := backend.writeMultipartManifest("stale-bucket", oldID, oldManifest); err != nil {
		t.Fatalf("write old manifest: %v", err)
	}
	markUploadTreeOld(t, backend.multipartUploadDir("stale-bucket", oldID), time.Now().UTC().Add(-2*time.Hour))

	freshManifest, err := backend.readMultipartManifest(context.Background(), "stale-bucket", freshID)
	if err != nil {
		t.Fatalf("read fresh manifest: %v", err)
	}
	freshManifest.CreatedAt = time.Now().UTC().Add(-10 * time.Minute)
	if err := backend.writeMultipartManifest("stale-bucket", freshID, freshManifest); err != nil {
		t.Fatalf("write fresh manifest: %v", err)
	}

	res, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{StaleAfter: time.Hour})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}
	if res.BucketsScanned != 1 {
		t.Fatalf("unexpected buckets scanned: %d", res.BucketsScanned)
	}
	if res.UploadsScanned != 2 {
		t.Fatalf("unexpected uploads scanned: %d", res.UploadsScanned)
	}
	if res.StaleCandidatesFound != 1 {
		t.Fatalf("unexpected stale candidates: %d", res.StaleCandidatesFound)
	}
	if res.UploadsRemoved != 1 {
		t.Fatalf("unexpected uploads removed: %d", res.UploadsRemoved)
	}

	if _, err := os.Stat(oldManifestPath); !os.IsNotExist(err) {
		t.Fatalf("expected stale upload removed, stat err=%v", err)
	}
	if _, err := os.Stat(backend.multipartManifestPath("stale-bucket", freshID)); err != nil {
		t.Fatalf("expected fresh upload to remain: %v", err)
	}
}

func TestSweepStaleMultipartUploadsRespectsRemovalLimit(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "limit-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	for i := 0; i < 3; i++ {
		uploadID, err := backend.CreateMultipartUpload(context.Background(), "limit-bucket", "obj.txt", ObjectMetadata{})
		if err != nil {
			t.Fatalf("CreateMultipartUpload %d error: %v", i, err)
		}
		manifest, err := backend.readMultipartManifest(context.Background(), "limit-bucket", uploadID)
		if err != nil {
			t.Fatalf("read manifest %d: %v", i, err)
		}
		manifest.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
		if err := backend.writeMultipartManifest("limit-bucket", uploadID, manifest); err != nil {
			t.Fatalf("write manifest %d: %v", i, err)
		}
		markUploadTreeOld(t, backend.multipartUploadDir("limit-bucket", uploadID), time.Now().UTC().Add(-2*time.Hour))
	}

	res, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{
		StaleAfter:  time.Hour,
		MaxRemovals: 1,
	})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}
	if res.UploadsRemoved != 1 {
		t.Fatalf("expected one removal, got %d", res.UploadsRemoved)
	}
	if res.SkippedByRemovalLimit != 2 {
		t.Fatalf("expected two skipped by limit, got %d", res.SkippedByRemovalLimit)
	}
}

func TestSweepStaleMultipartUploadsRemovesOldestFirstWhenLimited(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "oldest-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	type uploadState struct {
		id  string
		age time.Duration
		key string
	}
	states := []uploadState{{age: 3 * time.Hour, key: "a.txt"}, {age: 2 * time.Hour, key: "b.txt"}, {age: 90 * time.Minute, key: "c.txt"}}
	for i := range states {
		uploadID, err := backend.CreateMultipartUpload(context.Background(), "oldest-bucket", states[i].key, ObjectMetadata{})
		if err != nil {
			t.Fatalf("CreateMultipartUpload %d error: %v", i, err)
		}
		states[i].id = uploadID
		manifest, err := backend.readMultipartManifest(context.Background(), "oldest-bucket", uploadID)
		if err != nil {
			t.Fatalf("read manifest %d: %v", i, err)
		}
		manifest.CreatedAt = time.Now().UTC().Add(-states[i].age)
		if err := backend.writeMultipartManifest("oldest-bucket", uploadID, manifest); err != nil {
			t.Fatalf("write manifest %d: %v", i, err)
		}
		markUploadTreeOld(t, backend.multipartUploadDir("oldest-bucket", uploadID), time.Now().UTC().Add(-states[i].age))
	}

	_, err = backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{
		StaleAfter:  time.Hour,
		MaxRemovals: 1,
	})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}

	oldestID := states[0].id
	if _, err := os.Stat(backend.multipartUploadDir("oldest-bucket", oldestID)); !os.IsNotExist(err) {
		t.Fatalf("expected oldest upload removed, stat err=%v", err)
	}
	for _, s := range states[1:] {
		if _, err := os.Stat(backend.multipartUploadDir("oldest-bucket", s.id)); err != nil {
			t.Fatalf("expected newer upload retained: %v", err)
		}
	}
}

func TestSweepStaleMultipartUploadsCorruptRetentionPolicy(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "corrupt-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	uploadDir := backend.multipartUploadDir("corrupt-bucket", "up-corrupt")
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		t.Fatalf("mkdir upload dir: %v", err)
	}
	manifestPath := filepath.Join(uploadDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("bad-json"), 0o600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(uploadDir, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes upload dir: %v", err)
	}
	if err := os.Chtimes(manifestPath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes manifest: %v", err)
	}

	res, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{
		StaleAfter:           time.Hour,
		RemoveCorruptUploads: false,
	})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}
	if res.CorruptedUploadsFound != 1 {
		t.Fatalf("unexpected corrupted uploads found: %d", res.CorruptedUploadsFound)
	}
	if res.CorruptedUploadsKept != 1 {
		t.Fatalf("unexpected corrupted uploads kept: %d", res.CorruptedUploadsKept)
	}
	if _, err := os.Stat(uploadDir); err != nil {
		t.Fatalf("expected corrupt upload kept: %v", err)
	}
}

func TestSweepStaleMultipartUploadsHandlesMissingCreatedAtAsCorrupt(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "missing-created-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	uploadID, err := backend.CreateMultipartUpload(context.Background(), "missing-created-bucket", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	manifest, err := backend.readMultipartManifest(context.Background(), "missing-created-bucket", uploadID)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	manifest.CreatedAt = time.Time{}
	if err := backend.writeMultipartManifest("missing-created-bucket", uploadID, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	markUploadTreeOld(t, backend.multipartUploadDir("missing-created-bucket", uploadID), time.Now().UTC().Add(-2*time.Hour))

	res, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{
		StaleAfter:           time.Hour,
		RemoveCorruptUploads: true,
	})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}
	if res.CorruptedUploadsFound != 1 {
		t.Fatalf("expected one corrupt upload, got %d", res.CorruptedUploadsFound)
	}
	if res.UploadsRemoved != 1 {
		t.Fatalf("expected one upload removed, got %d", res.UploadsRemoved)
	}
}

func TestSweepStaleMultipartUploadsCleansStaleTempFiles(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "tmp-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	uploadID, err := backend.CreateMultipartUpload(context.Background(), "tmp-bucket", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	tmpPartPath := filepath.Join(backend.multipartUploadDir("tmp-bucket", uploadID), "part-orphan.tmp")
	if err := os.WriteFile(tmpPartPath, []byte("temp"), 0o600); err != nil {
		t.Fatalf("write temp part: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(tmpPartPath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes temp part: %v", err)
	}

	res, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{
		StaleAfter:            24 * time.Hour,
		CleanupTemporaryFiles: true,
		TempFileStaleAfter:    time.Hour,
	})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}
	if res.TempFilesRemoved != 1 {
		t.Fatalf("expected one temp file removed, got %d", res.TempFilesRemoved)
	}
	if _, err := os.Stat(tmpPartPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file removed, stat err=%v", err)
	}
}

func TestSweepStaleMultipartUploadsUsesLatestUploadActivity(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "activity-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	uploadID, err := backend.CreateMultipartUpload(context.Background(), "activity-bucket", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	manifest, err := backend.readMultipartManifest(context.Background(), "activity-bucket", uploadID)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	manifest.CreatedAt = time.Now().UTC().Add(-3 * time.Hour)
	if err := backend.writeMultipartManifest("activity-bucket", uploadID, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	partPath := filepath.Join(backend.multipartUploadDir("activity-bucket", uploadID), "part-00001.bin")
	if err := os.WriteFile(partPath, []byte("recent"), 0o600); err != nil {
		t.Fatalf("write part: %v", err)
	}

	res, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{StaleAfter: time.Hour})
	if err != nil {
		t.Fatalf("SweepStaleMultipartUploads error: %v", err)
	}
	if res.UploadsRemoved != 0 {
		t.Fatalf("expected active upload to remain, removed=%d", res.UploadsRemoved)
	}
}

func TestSweepStaleMultipartUploadsRejectsInvalidAge(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if _, err := backend.SweepStaleMultipartUploads(context.Background(), time.Now().UTC(), MultipartSweepOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request error, got %v", err)
	}
}

func TestSweepStaleMultipartUploadsHonorsCanceledContext(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "cancel-sweep"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if _, err := backend.CreateMultipartUpload(context.Background(), "cancel-sweep", "obj.txt", ObjectMetadata{}); err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := backend.SweepStaleMultipartUploads(ctx, time.Now().UTC(), MultipartSweepOptions{StaleAfter: time.Hour}); err == nil {
		t.Fatal("expected context cancellation error")
	}
}
