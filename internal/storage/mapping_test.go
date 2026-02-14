package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeKeyFilesystemSafe(t *testing.T) {
	t.Parallel()
	encoded := EncodeKey("../../etc/passwd")
	if strings.Contains(encoded, "/") || strings.Contains(encoded, "..") {
		t.Fatalf("encoded key is not filesystem safe: %q", encoded)
	}
}

func TestObjectAndMetaPathsStayWithinBucketRoot(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	bucket := "safe-bucket"
	key := "../../etc/passwd"

	objPath := backend.objectPath(bucket, key)
	metaPath := backend.metaPath(bucket, key)
	bucketRoot := backend.bucketDir(bucket)

	if rel, err := filepath.Rel(bucketRoot, objPath); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("object path escaped bucket root: %q", objPath)
	}
	if rel, err := filepath.Rel(bucketRoot, metaPath); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("meta path escaped bucket root: %q", metaPath)
	}
}
