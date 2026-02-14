package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"storas/internal/storage"
)

type snapshotObjectMetadata struct {
	Key string `json:"key"`
}

func TestIntegrationBackupRestoreFromFilesystemSnapshot(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	ctx := context.Background()

	env.mustReq("PUT", "/restore-bucket", nil, 200)
	enableBody := bytes.NewBufferString(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	env.mustReq("PUT", "/restore-bucket?versioning", enableBody, 200)
	env.mustReq("PUT", "/restore-bucket/logs/app.txt", bytes.NewBufferString("v1"), 200)
	env.mustReq("PUT", "/restore-bucket/logs/app.txt", bytes.NewBufferString("v2"), 200)
	env.mustReq("PUT", "/restore-bucket/logs/other.txt", bytes.NewBufferString("other"), 200)

	uploadID, err := env.backend.CreateMultipartUpload(ctx, "restore-bucket", "multipart/incomplete.bin", storage.ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	if _, err := env.backend.UploadPart(ctx, "restore-bucket", "multipart/incomplete.bin", uploadID, 1, strings.NewReader("partial-data")); err != nil {
		t.Fatalf("UploadPart error: %v", err)
	}

	snapshotDir := filepath.Join(t.TempDir(), "snapshot-data")
	if err := copyDir(env.backendRoot(), snapshotDir); err != nil {
		t.Fatalf("copyDir snapshot error: %v", err)
	}

	restored, err := storage.NewFSBackend(snapshotDir, 25*1024*1024*1024)
	if err != nil {
		t.Fatalf("NewFSBackend restore error: %v", err)
	}

	if err := verifyFilesystemIntegrity(snapshotDir); err != nil {
		t.Fatalf("verifyFilesystemIntegrity error: %v", err)
	}
	if err := verifyRestoredBehavior(ctx, restored, uploadID); err != nil {
		t.Fatalf("verifyRestoredBehavior error: %v", err)
	}
}

func verifyRestoredBehavior(ctx context.Context, backend *storage.FSBackend, uploadID string) error {
	buckets, err := backend.ListBuckets(ctx)
	if err != nil {
		return err
	}
	if len(buckets) != 1 || buckets[0] != "restore-bucket" {
		return errors.New("restored buckets mismatch")
	}
	rc, _, err := backend.GetObject(ctx, "restore-bucket", "logs/app.txt")
	if err != nil {
		return err
	}
	defer rc.Close()
	bytesBody, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	if string(bytesBody) != "v2" {
		return errors.New("restored current object payload mismatch")
	}
	versions, err := backend.ListObjectVersions(ctx, "restore-bucket", storage.ListObjectVersionsOptions{MaxKeys: 1000})
	if err != nil {
		return err
	}
	if len(versions.Versions) < 2 {
		return errors.New("restored versions missing")
	}
	uploads, err := backend.ListMultipartUploads(ctx, "restore-bucket", storage.MultipartUploadListOptions{MaxUploads: 1000})
	if err != nil {
		return err
	}
	if len(uploads.Uploads) != 1 || uploads.Uploads[0].UploadID != uploadID {
		return errors.New("restored multipart upload missing")
	}
	return nil
}

func verifyFilesystemIntegrity(root string) error {
	bucketsRoot := filepath.Join(root, "buckets")
	buckets, err := os.ReadDir(bucketsRoot)
	if err != nil {
		return err
	}
	for _, bucketEntry := range buckets {
		if !bucketEntry.IsDir() {
			continue
		}
		bucketDir := filepath.Join(bucketsRoot, bucketEntry.Name())
		if err := verifyCurrentObjectPairs(bucketDir); err != nil {
			return err
		}
		if err := verifyVersionObjectPairs(bucketDir); err != nil {
			return err
		}
		if err := verifyMultipartPairs(bucketDir); err != nil {
			return err
		}
	}
	return nil
}

func verifyCurrentObjectPairs(bucketDir string) error {
	metaDir := filepath.Join(bucketDir, "meta")
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		metaPath := filepath.Join(metaDir, entry.Name())
		bytesMeta, err := os.ReadFile(metaPath)
		if err != nil {
			return err
		}
		var meta snapshotObjectMetadata
		if err := json.Unmarshal(bytesMeta, &meta); err != nil {
			return err
		}
		if strings.TrimSpace(meta.Key) == "" {
			return errors.New("metadata key missing")
		}
		encodedKey := storage.EncodeKey(meta.Key)
		objectPath := filepath.Join(bucketDir, "objects", encodedKey+".bin")
		if _, err := os.Stat(objectPath); err != nil {
			return err
		}
	}
	return nil
}

func verifyVersionObjectPairs(bucketDir string) error {
	metaRoot := filepath.Join(bucketDir, "versions")
	if _, err := os.Stat(metaRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return filepath.WalkDir(metaRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rel, err := filepath.Rel(metaRoot, path)
		if err != nil {
			return err
		}
		payloadPath := filepath.Join(metaRoot, strings.TrimSuffix(rel, ".json")+".bin")
		if _, err := os.Stat(payloadPath); err != nil {
			return err
		}
		return nil
	})
}

func verifyMultipartPairs(bucketDir string) error {
	mpRoot := filepath.Join(bucketDir, "multipart")
	entries, err := os.ReadDir(mpRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		uploadDir := filepath.Join(mpRoot, entry.Name())
		if _, err := os.Stat(filepath.Join(uploadDir, "manifest.json")); err != nil {
			return err
		}
		partEntries, err := os.ReadDir(uploadDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, part := range partEntries {
			if part.IsDir() || !strings.HasPrefix(part.Name(), "part-") || !strings.HasSuffix(part.Name(), ".bin") {
				continue
			}
			metaPath := filepath.Join(uploadDir, strings.TrimSuffix(part.Name(), ".bin")+".json")
			if _, err := os.Stat(metaPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *integrationEnv) backendRoot() string {
	return e.dataRoot
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		info, err := d.Info()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
}
