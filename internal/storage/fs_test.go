package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestFSBackendObjectLifecycle(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}

	if err := backend.CreateBucket(context.Background(), "backup-data"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	input := []byte("hello object storage")
	obj, err := backend.PutObject(context.Background(), "backup-data", "dir/file.txt", bytes.NewReader(input), ObjectMetadata{
		ContentType:  "text/plain",
		UserMetadata: map[string]string{"owner": "qa"},
		ObjectTags:   map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("PutObject error: %v", err)
	}
	if obj.ETag == "" || obj.Size != int64(len(input)) {
		t.Fatalf("unexpected object info: %+v", obj)
	}

	rc, meta, err := backend.GetObject(context.Background(), "backup-data", "dir/file.txt")
	if err != nil {
		t.Fatalf("GetObject error: %v", err)
	}
	defer rc.Close()
	actual, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(actual) != string(input) {
		t.Fatalf("unexpected payload %q", string(actual))
	}
	if meta.UserMetadata["owner"] != "qa" {
		t.Fatalf("unexpected user metadata: %+v", meta.UserMetadata)
	}
	if meta.ObjectTags["env"] != "prod" {
		t.Fatalf("unexpected object tags: %+v", meta.ObjectTags)
	}

	if err := backend.DeleteObject(context.Background(), "backup-data", "dir/file.txt"); err != nil {
		t.Fatalf("DeleteObject error: %v", err)
	}
}

func TestFSBackendListObjectsAndBucketDeleteConstraint(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "logs-data"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	for _, key := range []string{"a.txt", "folder/b.txt", "folder/c.txt"} {
		if _, err := backend.PutObject(context.Background(), "logs-data", key, bytes.NewBufferString(key), ObjectMetadata{}); err != nil {
			t.Fatalf("PutObject(%s) error: %v", key, err)
		}
	}

	res, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{Prefix: "folder/", Delimiter: "/", MaxKeys: 100})
	if err != nil {
		t.Fatalf("ListObjectsV2 error: %v", err)
	}
	if len(res.Objects) != 2 {
		t.Fatalf("expected two objects under prefix, got %d", len(res.Objects))
	}

	zeroRes, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{MaxKeys: 0})
	if err != nil {
		t.Fatalf("ListObjectsV2 max-keys=0 error: %v", err)
	}
	if len(zeroRes.Objects) != 0 {
		t.Fatalf("expected zero objects for max-keys=0, got %d", len(zeroRes.Objects))
	}

	if err := backend.DeleteBucket(context.Background(), "logs-data"); err == nil {
		t.Fatal("expected bucket not empty error")
	}
}

func TestFSBackendListObjectsDelimiterMaxKeysSemantics(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "logs-data"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	for _, key := range []string{"a/1.txt", "a/2.txt", "b/1.txt", "c.txt"} {
		if _, err := backend.PutObject(context.Background(), "logs-data", key, bytes.NewBufferString(key), ObjectMetadata{}); err != nil {
			t.Fatalf("PutObject(%s) error: %v", key, err)
		}
	}

	res, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{
		Delimiter: "/",
		MaxKeys:   1,
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 delimiter maxkeys error: %v", err)
	}
	if len(res.CommonPrefixes) != 1 || res.CommonPrefixes[0] != "a/" {
		t.Fatalf("unexpected common prefixes: %+v", res.CommonPrefixes)
	}
	if len(res.Objects) != 0 {
		t.Fatalf("expected no objects with max-keys=1 and first entry a prefix, got %d", len(res.Objects))
	}
	if !res.IsTruncated || res.NextContinuationToken == "" {
		t.Fatalf("expected truncated response with continuation token, got %+v", res)
	}

	res2, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{
		Delimiter:         "/",
		MaxKeys:           1,
		ContinuationToken: res.NextContinuationToken,
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 continuation error: %v", err)
	}
	if len(res2.CommonPrefixes)+len(res2.Objects) == 0 {
		t.Fatalf("expected additional entries after continuation, got %+v", res2)
	}
}

func TestFSBackendListObjectsStartAfterAndContinuationPrecedence(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "logs-data"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	for _, key := range []string{"a.txt", "b.txt", "c.txt"} {
		if _, err := backend.PutObject(context.Background(), "logs-data", key, bytes.NewBufferString(key), ObjectMetadata{}); err != nil {
			t.Fatalf("PutObject(%s) error: %v", key, err)
		}
	}

	afterRes, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{
		StartAfter: "a.txt",
		MaxKeys:    1000,
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 start-after error: %v", err)
	}
	if len(afterRes.Objects) != 2 || afterRes.Objects[0].Key != "b.txt" {
		t.Fatalf("unexpected start-after result: %+v", afterRes.Objects)
	}

	first, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{MaxKeys: 1})
	if err != nil {
		t.Fatalf("ListObjectsV2 first page error: %v", err)
	}
	if first.NextContinuationToken == "" {
		t.Fatalf("expected continuation token, got %+v", first)
	}
	precedenceRes, err := backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{
		StartAfter:        "z.txt",
		ContinuationToken: first.NextContinuationToken,
		MaxKeys:           1000,
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 precedence error: %v", err)
	}
	if len(precedenceRes.Objects) == 0 || precedenceRes.Objects[0].Key != "b.txt" {
		t.Fatalf("expected continuation-token precedence over start-after, got %+v", precedenceRes.Objects)
	}
}

func TestFSBackendRangeAndSizeLimit(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), 100)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "range-data"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	limitedBackend, err := NewFSBackend(t.TempDir(), 5)
	if err != nil {
		t.Fatalf("NewFSBackend limited error: %v", err)
	}
	if err := limitedBackend.CreateBucket(context.Background(), "range-data"); err != nil {
		t.Fatalf("CreateBucket limited error: %v", err)
	}

	if _, err := limitedBackend.PutObject(context.Background(), "range-data", "big.txt", bytes.NewBufferString("123456"), ObjectMetadata{}); err == nil {
		t.Fatal("expected entity too large error")
	}

	if _, err := backend.PutObject(context.Background(), "range-data", "small.txt", bytes.NewBufferString("0123456789"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject small error: %v", err)
	}

	rc, _, start, end, err := backend.GetObjectRange(context.Background(), "range-data", "small.txt", "bytes=2-5")
	if err != nil {
		t.Fatalf("GetObjectRange error: %v", err)
	}
	defer rc.Close()
	if start != 2 || end != 5 {
		t.Fatalf("unexpected range start/end: %d-%d", start, end)
	}
	chunk, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll range error: %v", err)
	}
	if string(chunk) != "2345" {
		t.Fatalf("unexpected range payload: %q", string(chunk))
	}
}

func TestEncodeDecodeKeyRoundTrip(t *testing.T) {
	t.Parallel()
	key := "folder with spaces/文件.txt"
	encoded := EncodeKey(key)
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey error: %v", err)
	}
	if decoded != key {
		t.Fatalf("round trip mismatch: %q != %q", decoded, key)
	}
}

func TestFSBackendBucketNameValidationRules(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}

	if err := backend.CreateBucket(context.Background(), "logs.prod"); err != nil {
		t.Fatalf("CreateBucket dotted name error: %v", err)
	}
	if err := backend.HeadBucket(context.Background(), "logs.prod"); err != nil {
		t.Fatalf("HeadBucket dotted name error: %v", err)
	}

	for _, bucket := range []string{"192.168.1.10", "bad..dots", "UpperCase"} {
		if err := backend.CreateBucket(context.Background(), bucket); !errors.Is(err, ErrInvalidBucketName) {
			t.Fatalf("expected ErrInvalidBucketName for %q, got %v", bucket, err)
		}
	}
}

func TestFSBackendListObjectsInvalidContinuationToken(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "logs-data"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	_, err = backend.ListObjectsV2(context.Background(), "logs-data", ListObjectsOptions{
		ContinuationToken: "%%%bad",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestFSBackendBucketOpsHonorCanceledContext(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := backend.CreateBucket(ctx, "cancel-bucket"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from CreateBucket, got %v", err)
	}
	if _, err := backend.ListBuckets(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from ListBuckets, got %v", err)
	}
}

func TestFSBackendBucketMetadataCreationDatePersists(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "meta-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	first, err := backend.GetBucketInfo(context.Background(), "meta-bucket")
	if err != nil {
		t.Fatalf("GetBucketInfo error: %v", err)
	}
	if first.Name != "meta-bucket" {
		t.Fatalf("unexpected bucket name: %q", first.Name)
	}
	if first.CreationDate.IsZero() {
		t.Fatal("expected non-zero creation date")
	}

	time.Sleep(5 * time.Millisecond)
	second, err := backend.GetBucketInfo(context.Background(), "meta-bucket")
	if err != nil {
		t.Fatalf("second GetBucketInfo error: %v", err)
	}
	if !first.CreationDate.Equal(second.CreationDate) {
		t.Fatalf("expected stable creation date, first=%s second=%s", first.CreationDate, second.CreationDate)
	}
}

func TestFSBackendBucketVersioningState(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "ver-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	initial, err := backend.GetBucketVersioning(context.Background(), "ver-bucket")
	if err != nil {
		t.Fatalf("GetBucketVersioning initial error: %v", err)
	}
	if initial != BucketVersioningOff {
		t.Fatalf("expected Off status by default, got %s", initial)
	}

	if err := backend.PutBucketVersioning(context.Background(), "ver-bucket", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning enabled error: %v", err)
	}
	enabled, err := backend.GetBucketVersioning(context.Background(), "ver-bucket")
	if err != nil {
		t.Fatalf("GetBucketVersioning enabled error: %v", err)
	}
	if enabled != BucketVersioningEnabled {
		t.Fatalf("expected Enabled status, got %s", enabled)
	}

	if err := backend.PutBucketVersioning(context.Background(), "ver-bucket", BucketVersioningSuspended); err != nil {
		t.Fatalf("PutBucketVersioning suspended error: %v", err)
	}
	suspended, err := backend.GetBucketVersioning(context.Background(), "ver-bucket")
	if err != nil {
		t.Fatalf("GetBucketVersioning suspended error: %v", err)
	}
	if suspended != BucketVersioningSuspended {
		t.Fatalf("expected Suspended status, got %s", suspended)
	}

	if err := backend.PutBucketVersioning(context.Background(), "ver-bucket", BucketVersioningOff); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for unsupported persisted state, got %v", err)
	}
}

func TestFSBackendObjectVersionChainsAndDeleteMarkers(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "ver-obj"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if _, err := backend.PutObject(context.Background(), "ver-obj", "key.txt", bytes.NewBufferString("legacy"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject legacy error: %v", err)
	}
	if err := backend.PutBucketVersioning(context.Background(), "ver-obj", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning enabled error: %v", err)
	}

	v1, err := backend.PutObject(context.Background(), "ver-obj", "key.txt", bytes.NewBufferString("v1"), ObjectMetadata{})
	if err != nil {
		t.Fatalf("PutObject v1 error: %v", err)
	}
	if v1.VersionID == "" || v1.VersionID == nullVersionID {
		t.Fatalf("expected non-null version id for enabled bucket, got %q", v1.VersionID)
	}
	v2, err := backend.PutObject(context.Background(), "ver-obj", "key.txt", bytes.NewBufferString("v2"), ObjectMetadata{})
	if err != nil {
		t.Fatalf("PutObject v2 error: %v", err)
	}
	if v2.VersionID == "" || v2.VersionID == v1.VersionID {
		t.Fatalf("expected unique version ids, v1=%q v2=%q", v1.VersionID, v2.VersionID)
	}

	rc, _, err := backend.GetObjectVersion(context.Background(), "ver-obj", "key.txt", v1.VersionID)
	if err != nil {
		t.Fatalf("GetObjectVersion v1 error: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read v1 error: %v", err)
	}
	if string(data) != "v1" {
		t.Fatalf("expected v1 payload, got %q", string(data))
	}

	del, err := backend.DeleteObjectVersion(context.Background(), "ver-obj", "key.txt", "")
	if err != nil {
		t.Fatalf("DeleteObject current error: %v", err)
	}
	if !del.DeleteMarker || del.VersionID == "" {
		t.Fatalf("expected delete marker result, got %+v", del)
	}
	if _, _, err := backend.GetObject(context.Background(), "ver-obj", "key.txt"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("expected ErrNoSuchKey after delete marker, got %v", err)
	}
}

func TestFSBackendDeleteExplicitVersionAndListVersions(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "ver-list"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketVersioning(context.Background(), "ver-list", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning enabled error: %v", err)
	}
	v1, err := backend.PutObject(context.Background(), "ver-list", "a.txt", bytes.NewBufferString("a1"), ObjectMetadata{})
	if err != nil {
		t.Fatalf("PutObject v1 error: %v", err)
	}
	v2, err := backend.PutObject(context.Background(), "ver-list", "a.txt", bytes.NewBufferString("a2"), ObjectMetadata{})
	if err != nil {
		t.Fatalf("PutObject v2 error: %v", err)
	}
	if _, err := backend.DeleteObjectVersion(context.Background(), "ver-list", "a.txt", v2.VersionID); err != nil {
		t.Fatalf("DeleteObjectVersion explicit error: %v", err)
	}
	if _, _, err := backend.GetObjectVersion(context.Background(), "ver-list", "a.txt", v2.VersionID); !errors.Is(err, ErrNoSuchVersion) {
		t.Fatalf("expected ErrNoSuchVersion for deleted version, got %v", err)
	}
	rc, _, err := backend.GetObject(context.Background(), "ver-list", "a.txt")
	if err != nil {
		t.Fatalf("GetObject latest fallback error: %v", err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if string(body) != "a1" {
		t.Fatalf("expected rollback to v1 payload, got %q", string(body))
	}

	listed, err := backend.ListObjectVersions(context.Background(), "ver-list", ListObjectVersionsOptions{Prefix: "a", MaxKeys: 1000})
	if err != nil {
		t.Fatalf("ListObjectVersions error: %v", err)
	}
	if len(listed.Versions) == 0 {
		t.Fatal("expected at least one version entry")
	}
	foundV1 := false
	for _, v := range listed.Versions {
		if v.VersionID == v1.VersionID {
			foundV1 = true
		}
	}
	if !foundV1 {
		t.Fatalf("expected to find v1 version %q in listing: %+v", v1.VersionID, listed.Versions)
	}
}

func TestFSBackendDeleteObjectMissingBucketReturnsNoSuchBucket(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.DeleteObject(context.Background(), "missing", "key.txt"); !errors.Is(err, ErrNoSuchBucket) {
		t.Fatalf("expected ErrNoSuchBucket, got %v", err)
	}
}

func TestFSBackendBucketLifecycleCRUD(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "life-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	_, err = backend.GetBucketLifecycle(context.Background(), "life-bucket")
	if !errors.Is(err, ErrNoSuchLifecycleConfiguration) {
		t.Fatalf("expected ErrNoSuchLifecycleConfiguration, got %v", err)
	}

	in := LifecycleConfiguration{
		Rules: []LifecycleRule{
			{ID: "rule-1", Status: "Enabled", Prefix: "logs/", ExpirationDays: 30, AbortIncompleteUploadDays: 7},
		},
	}
	if err := backend.PutBucketLifecycle(context.Background(), "life-bucket", in); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	out, err := backend.GetBucketLifecycle(context.Background(), "life-bucket")
	if err != nil {
		t.Fatalf("GetBucketLifecycle error: %v", err)
	}
	if len(out.Rules) != 1 || out.Rules[0].ID != "rule-1" || out.Rules[0].ExpirationDays != 30 {
		t.Fatalf("unexpected lifecycle config: %+v", out)
	}
	if err := backend.DeleteBucketLifecycle(context.Background(), "life-bucket"); err != nil {
		t.Fatalf("DeleteBucketLifecycle error: %v", err)
	}
	_, err = backend.GetBucketLifecycle(context.Background(), "life-bucket")
	if !errors.Is(err, ErrNoSuchLifecycleConfiguration) {
		t.Fatalf("expected ErrNoSuchLifecycleConfiguration after delete, got %v", err)
	}
}

func TestFSBackendBucketPolicyCRUD(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "policy-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	if _, err := backend.GetBucketPolicy(context.Background(), "policy-bucket"); !errors.Is(err, ErrNoSuchBucketPolicy) {
		t.Fatalf("expected ErrNoSuchBucketPolicy, got %v", err)
	}

	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*"}]}`)
	if err := backend.PutBucketPolicy(context.Background(), "policy-bucket", policy); err != nil {
		t.Fatalf("PutBucketPolicy error: %v", err)
	}
	out, err := backend.GetBucketPolicy(context.Background(), "policy-bucket")
	if err != nil {
		t.Fatalf("GetBucketPolicy error: %v", err)
	}
	if string(out) != string(policy) {
		t.Fatalf("unexpected persisted policy: %s", string(out))
	}
	if err := backend.DeleteBucketPolicy(context.Background(), "policy-bucket"); err != nil {
		t.Fatalf("DeleteBucketPolicy error: %v", err)
	}
	if _, err := backend.GetBucketPolicy(context.Background(), "policy-bucket"); !errors.Is(err, ErrNoSuchBucketPolicy) {
		t.Fatalf("expected ErrNoSuchBucketPolicy after delete, got %v", err)
	}
}

func TestFSBackendObjectOpsHonorCanceledContext(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "cancel-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if _, err := backend.PutObject(context.Background(), "cancel-bucket", "obj.txt", bytes.NewBufferString("hello"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject setup error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := backend.GetObject(ctx, "cancel-bucket", "obj.txt"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from GetObject, got %v", err)
	}
	if _, _, _, _, err := backend.GetObjectRange(ctx, "cancel-bucket", "obj.txt", "bytes=0-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from GetObjectRange, got %v", err)
	}
	if _, err := backend.ListObjectsV2(ctx, "cancel-bucket", ListObjectsOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from ListObjectsV2, got %v", err)
	}
}

func TestFSBackendVersionIDsRemainUniqueUnderParallelWritesAndDeletes(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "parallel-version-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketVersioning(ctx, "parallel-version-bucket", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning error: %v", err)
	}

	const (
		workers    = 16
		iterations = 24
	)
	expectedIDs := workers*iterations + workers*(iterations/2)

	seen := make(map[string]struct{}, expectedIDs)
	var seenMu sync.Mutex
	recordID := func(id string) error {
		if id == "" || id == nullVersionID {
			return fmt.Errorf("unexpected version id %q", id)
		}
		seenMu.Lock()
		defer seenMu.Unlock()
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate version id: %s", id)
		}
		seen[id] = struct{}{}
		return nil
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("obj-%02d.txt", i%3)
				obj, putErr := backend.PutObject(ctx, "parallel-version-bucket", key, bytes.NewBufferString(fmt.Sprintf("worker=%d iter=%d", worker, i)), ObjectMetadata{})
				if putErr != nil {
					errCh <- putErr
					return
				}
				if recErr := recordID(obj.VersionID); recErr != nil {
					errCh <- recErr
					return
				}
				if i%2 == 0 {
					delRes, delErr := backend.DeleteObjectVersion(ctx, "parallel-version-bucket", key, "")
					if delErr != nil {
						errCh <- delErr
						return
					}
					if recErr := recordID(delRes.VersionID); recErr != nil {
						errCh <- recErr
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
			t.Fatalf("parallel versioning run failed: %v", runErr)
		}
	}

	if len(seen) != expectedIDs {
		t.Fatalf("expected %d unique version ids, got %d", expectedIDs, len(seen))
	}

	listed := make(map[string]struct{}, expectedIDs)
	opts := ListObjectVersionsOptions{MaxKeys: 1000}
	for {
		page, listErr := backend.ListObjectVersions(ctx, "parallel-version-bucket", opts)
		if listErr != nil {
			t.Fatalf("ListObjectVersions error: %v", listErr)
		}
		for _, v := range page.Versions {
			if _, ok := listed[v.VersionID]; ok {
				t.Fatalf("duplicate version id in listing: %s", v.VersionID)
			}
			listed[v.VersionID] = struct{}{}
		}
		if !page.IsTruncated {
			break
		}
		opts.KeyMarker = page.NextKeyMarker
		opts.VersionIDMarker = page.NextVersionIDMarker
	}
	if len(listed) != expectedIDs {
		t.Fatalf("expected %d versions in listing, got %d", expectedIDs, len(listed))
	}
}
