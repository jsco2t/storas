package storage

import (
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"storas/internal/s3"
)

const (
	defaultMaxObjectSize = int64(25 * 1024 * 1024 * 1024)
	nullVersionID        = "null"
	versionIDMaxAttempts = 32
)

type metadataOnDisk struct {
	Key           string            `json:"key"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	ETag          string            `json:"etag"`
	LastModified  time.Time         `json:"last_modified"`
	VersionID     string            `json:"version_id,omitempty"`
	DeleteMarker  bool              `json:"delete_marker,omitempty"`
	UserMetadata  map[string]string `json:"user_metadata"`
	ObjectTags    map[string]string `json:"object_tags,omitempty"`
}

type bucketMetadataOnDisk struct {
	CreationDate     time.Time `json:"creation_date"`
	VersioningStatus string    `json:"versioning_status,omitempty"`
}

type FSBackend struct {
	rootDir       string
	maxObjectSize int64
	mutationMu    sync.RWMutex
}

func NewFSBackend(rootDir string, maxObjectSize int64) (*FSBackend, error) {
	if strings.TrimSpace(rootDir) == "" {
		return nil, fmt.Errorf("root directory is required")
	}
	if maxObjectSize <= 0 {
		maxObjectSize = defaultMaxObjectSize
	}

	cleanRoot := filepath.Clean(rootDir)
	if err := os.MkdirAll(filepath.Join(cleanRoot, "buckets"), 0o755); err != nil {
		return nil, fmt.Errorf("create buckets root: %w", err)
	}

	return &FSBackend{rootDir: cleanRoot, maxObjectSize: maxObjectSize}, nil
}

func (b *FSBackend) CreateBucket(ctx context.Context, bucket string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if !s3.IsValidBucketName(bucket) {
		return ErrInvalidBucketName
	}
	b.mutationMu.Lock()
	defer b.mutationMu.Unlock()
	bucketDir := b.bucketDir(bucket)
	if _, err := os.Stat(bucketDir); err == nil {
		return ErrBucketExists
	}
	if err := os.MkdirAll(filepath.Join(bucketDir, "objects"), 0o755); err != nil {
		return fmt.Errorf("create bucket objects dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(bucketDir, "meta"), 0o755); err != nil {
		return fmt.Errorf("create bucket metadata dir: %w", err)
	}
	created := bucketMetadataOnDisk{CreationDate: time.Now().UTC()}
	bytes, err := json.Marshal(created)
	if err != nil {
		return fmt.Errorf("marshal bucket metadata: %w", err)
	}
	if err := writeFileAtomic(b.bucketMetaPath(bucket), bytes, 0o644); err != nil {
		return fmt.Errorf("write bucket metadata: %w", err)
	}
	return nil
}

func (b *FSBackend) DeleteBucket(ctx context.Context, bucket string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return err
	}

	objectEntries, err := os.ReadDir(filepath.Join(b.bucketDir(bucket), "meta"))
	if err != nil {
		return fmt.Errorf("read bucket metadata dir: %w", err)
	}
	if len(objectEntries) > 0 {
		return ErrBucketNotEmpty
	}

	multipartDir := filepath.Join(b.bucketDir(bucket), "multipart")
	mpEntries, err := os.ReadDir(multipartDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read bucket multipart dir: %w", err)
	}
	if len(mpEntries) > 0 {
		return ErrBucketNotEmpty
	}

	if err := os.RemoveAll(b.bucketDir(bucket)); err != nil {
		return fmt.Errorf("delete bucket: %w", err)
	}
	return nil
}

func (b *FSBackend) HeadBucket(ctx context.Context, bucket string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if !s3.IsValidBucketName(bucket) {
		return ErrInvalidBucketName
	}
	info, err := os.Stat(b.bucketDir(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNoSuchBucket
		}
		return fmt.Errorf("stat bucket: %w", err)
	}
	if !info.IsDir() {
		return ErrNoSuchBucket
	}
	return nil
}

func (b *FSBackend) ListBuckets(ctx context.Context) ([]string, error) {
	if err := ensureContext(ctx); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(b.rootDir, "buckets"))
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	buckets := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			buckets = append(buckets, entry.Name())
		}
	}
	sort.Strings(buckets)
	return buckets, nil
}

func (b *FSBackend) GetBucketInfo(ctx context.Context, bucket string) (BucketInfo, error) {
	if err := ensureContext(ctx); err != nil {
		return BucketInfo{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return BucketInfo{}, err
	}
	meta, err := b.readBucketMetadata(bucket)
	if err != nil {
		return BucketInfo{}, err
	}
	return BucketInfo{Name: bucket, CreationDate: meta.CreationDate.UTC()}, nil
}

func (b *FSBackend) GetBucketVersioning(ctx context.Context, bucket string) (BucketVersioningStatus, error) {
	if err := ensureContext(ctx); err != nil {
		return BucketVersioningOff, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return BucketVersioningOff, err
	}
	meta, err := b.readBucketMetadata(bucket)
	if err != nil {
		return BucketVersioningOff, err
	}
	switch BucketVersioningStatus(meta.VersioningStatus) {
	case BucketVersioningEnabled:
		return BucketVersioningEnabled, nil
	case BucketVersioningSuspended:
		return BucketVersioningSuspended, nil
	default:
		return BucketVersioningOff, nil
	}
}

func (b *FSBackend) PutBucketVersioning(ctx context.Context, bucket string, status BucketVersioningStatus) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return err
	}
	switch status {
	case BucketVersioningEnabled, BucketVersioningSuspended:
	default:
		return ErrInvalidRequest
	}
	meta, err := b.readBucketMetadata(bucket)
	if err != nil {
		return err
	}
	meta.VersioningStatus = string(status)
	if err := b.writeBucketMetadata(bucket, meta); err != nil {
		return err
	}
	if status == BucketVersioningEnabled {
		return b.migrateBucketLegacyObjectsToNullVersions(ctx, bucket)
	}
	return nil
}

func (b *FSBackend) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	if err := ensureContext(ctx); err != nil {
		return nil, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(b.bucketPolicyPath(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSuchBucketPolicy
		}
		return nil, fmt.Errorf("read bucket policy: %w", err)
	}
	return bytes, nil
}

func (b *FSBackend) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return err
	}
	if len(policy) == 0 {
		return ErrInvalidRequest
	}
	if err := os.MkdirAll(filepath.Dir(b.bucketPolicyPath(bucket)), 0o755); err != nil {
		return fmt.Errorf("ensure bucket policy path: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(b.bucketPolicyPath(bucket)), "bucket-policy-*.tmp")
	if err != nil {
		return fmt.Errorf("create bucket policy temp: %w", err)
	}
	if _, err := tmp.Write(policy); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write bucket policy temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync bucket policy temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close bucket policy temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), b.bucketPolicyPath(bucket)); err != nil {
		return fmt.Errorf("commit bucket policy: %w", err)
	}
	return nil
}

func (b *FSBackend) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return err
	}
	if err := os.Remove(b.bucketPolicyPath(bucket)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete bucket policy: %w", err)
	}
	return nil
}

func (b *FSBackend) GetBucketLifecycle(ctx context.Context, bucket string) (LifecycleConfiguration, error) {
	if err := ensureContext(ctx); err != nil {
		return LifecycleConfiguration{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return LifecycleConfiguration{}, err
	}
	bytes, err := os.ReadFile(b.bucketLifecyclePath(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return LifecycleConfiguration{}, ErrNoSuchLifecycleConfiguration
		}
		return LifecycleConfiguration{}, fmt.Errorf("read lifecycle: %w", err)
	}
	var cfg LifecycleConfiguration
	if err := json.Unmarshal(bytes, &cfg); err != nil {
		return LifecycleConfiguration{}, fmt.Errorf("decode lifecycle: %w", err)
	}
	return cfg, nil
}

func (b *FSBackend) PutBucketLifecycle(ctx context.Context, bucket string, cfg LifecycleConfiguration) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.bucketLifecyclePath(bucket)), 0o755); err != nil {
		return fmt.Errorf("ensure lifecycle path: %w", err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal lifecycle: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(b.bucketLifecyclePath(bucket)), "lifecycle-*.tmp")
	if err != nil {
		return fmt.Errorf("create lifecycle temp: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write lifecycle temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync lifecycle temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close lifecycle temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), b.bucketLifecyclePath(bucket)); err != nil {
		return fmt.Errorf("commit lifecycle: %w", err)
	}
	return nil
}

func (b *FSBackend) DeleteBucketLifecycle(ctx context.Context, bucket string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return err
	}
	_ = os.Remove(b.bucketLifecyclePath(bucket))
	return nil
}

func (b *FSBackend) PutObject(ctx context.Context, bucket, key string, body io.Reader, metadata ObjectMetadata) (ObjectInfo, error) {
	if err := ensureContext(ctx); err != nil {
		return ObjectInfo{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return ObjectInfo{}, err
	}
	if key == "" {
		return ObjectInfo{}, ErrNoSuchKey
	}
	b.mutationMu.Lock()
	defer b.mutationMu.Unlock()
	return b.putObjectUnderLock(ctx, bucket, key, body, metadata)
}

// putObjectUnderLock performs the write work for PutObject. Callers must hold
// b.mutationMu (write lock) before calling this method.
func (b *FSBackend) putObjectUnderLock(ctx context.Context, bucket, key string, body io.Reader, metadata ObjectMetadata) (ObjectInfo, error) {
	versioning, err := b.GetBucketVersioning(ctx, bucket)
	if err != nil {
		return ObjectInfo{}, err
	}
	if err := b.ensureLegacyNullVersion(ctx, bucket, key); err != nil {
		return ObjectInfo{}, err
	}

	versionID := nullVersionID
	if versioning == BucketVersioningEnabled {
		versionID, err = b.nextVersionID(bucket, key)
		if err != nil {
			return ObjectInfo{}, err
		}
	}

	payloadPath := b.objectPath(bucket, key)
	metaPath := b.metaPath(bucket, key)
	versionPayloadPath := b.objectVersionPath(bucket, key, versionID)
	versionMetaPath := b.objectVersionMetaPath(bucket, key, versionID)

	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o755); err != nil {
		return ObjectInfo{}, fmt.Errorf("ensure payload dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		return ObjectInfo{}, fmt.Errorf("ensure metadata dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(versionPayloadPath), 0o755); err != nil {
		return ObjectInfo{}, fmt.Errorf("ensure version payload dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(versionMetaPath), 0o755); err != nil {
		return ObjectInfo{}, fmt.Errorf("ensure version metadata dir: %w", err)
	}

	tmpPayload, err := os.CreateTemp(filepath.Dir(payloadPath), "obj-*.tmp")
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("create temp payload: %w", err)
	}
	defer func() { _ = os.Remove(tmpPayload.Name()) }()

	h := md5.New() //nolint:gosec // S3 ETag compatibility for single-part objects.
	limitedBody := io.LimitReader(body, b.maxObjectSize+1)
	written, err := io.Copy(io.MultiWriter(tmpPayload, h), limitedBody)
	if err != nil {
		_ = tmpPayload.Close()
		return ObjectInfo{}, fmt.Errorf("write payload: %w", err)
	}
	if written > b.maxObjectSize {
		_ = tmpPayload.Close()
		return ObjectInfo{}, ErrEntityTooLarge
	}
	if err := tmpPayload.Sync(); err != nil {
		_ = tmpPayload.Close()
		return ObjectInfo{}, fmt.Errorf("sync temp payload: %w", err)
	}
	if err := tmpPayload.Close(); err != nil {
		return ObjectInfo{}, fmt.Errorf("close temp payload: %w", err)
	}

	now := time.Now().UTC()
	etag := hex.EncodeToString(h.Sum(nil))
	metaRecord := metadataOnDisk{
		Key:           key,
		ContentType:   metadata.ContentType,
		ContentLength: written,
		ETag:          etag,
		LastModified:  now,
		VersionID:     versionID,
		UserMetadata:  cloneMap(metadata.UserMetadata),
		ObjectTags:    cloneMap(metadata.ObjectTags),
	}
	metaJSON, err := json.Marshal(metaRecord)
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("marshal metadata: %w", err)
	}

	tmpMeta, err := os.CreateTemp(filepath.Dir(metaPath), "meta-*.tmp")
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("create temp metadata: %w", err)
	}
	defer func() { _ = os.Remove(tmpMeta.Name()) }()

	if _, err := tmpMeta.Write(metaJSON); err != nil {
		_ = tmpMeta.Close()
		return ObjectInfo{}, fmt.Errorf("write metadata: %w", err)
	}
	if err := tmpMeta.Sync(); err != nil {
		_ = tmpMeta.Close()
		return ObjectInfo{}, fmt.Errorf("sync metadata: %w", err)
	}
	if err := tmpMeta.Close(); err != nil {
		return ObjectInfo{}, fmt.Errorf("close metadata: %w", err)
	}

	if err := os.Rename(tmpPayload.Name(), payloadPath); err != nil {
		return ObjectInfo{}, fmt.Errorf("commit payload: %w", err)
	}
	if err := os.Rename(tmpMeta.Name(), metaPath); err != nil {
		_ = os.Remove(payloadPath)
		return ObjectInfo{}, fmt.Errorf("commit metadata: %w", err)
	}
	if err := copyFile(payloadPath, versionPayloadPath); err != nil {
		return ObjectInfo{}, fmt.Errorf("commit version payload: %w", err)
	}
	if err := copyFile(metaPath, versionMetaPath); err != nil {
		return ObjectInfo{}, fmt.Errorf("commit version metadata: %w", err)
	}

	return ObjectInfo{
		Bucket:    bucket,
		Key:       key,
		Size:      written,
		ETag:      etag,
		Modified:  now,
		VersionID: versionID,
	}, nil
}

func (b *FSBackend) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, ObjectMetadata, error) {
	return b.GetObjectVersion(ctx, bucket, key, "")
}

func (b *FSBackend) GetObjectVersion(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, ObjectMetadata, error) {
	if err := ensureContext(ctx); err != nil {
		return nil, ObjectMetadata{}, err
	}
	b.mutationMu.RLock()
	defer b.mutationMu.RUnlock()
	return b.getObjectVersionUnlocked(ctx, bucket, key, versionID)
}

// getObjectVersionUnlocked opens the payload file for the given object version.
// Callers must hold b.mutationMu (at least read lock) before calling this method.
func (b *FSBackend) getObjectVersionUnlocked(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, ObjectMetadata, error) {
	meta, err := b.headObjectVersionUnlocked(ctx, bucket, key, versionID)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	if meta.DeleteMarker {
		return nil, ObjectMetadata{}, ErrNoSuchKey
	}
	payloadPath := b.objectPath(bucket, key)
	if meta.VersionID != "" {
		payloadPath = b.objectVersionPath(bucket, key, meta.VersionID)
	}
	file, err := os.Open(payloadPath)
	if err != nil {
		if os.IsNotExist(err) {
			if versionID != "" {
				return nil, ObjectMetadata{}, ErrNoSuchVersion
			}
			return nil, ObjectMetadata{}, ErrNoSuchKey
		}
		return nil, ObjectMetadata{}, fmt.Errorf("open payload: %w", err)
	}
	return file, meta, nil
}

func (b *FSBackend) GetObjectRange(ctx context.Context, bucket, key, rangeHeader string) (io.ReadCloser, ObjectMetadata, int64, int64, error) {
	return b.GetObjectRangeVersion(ctx, bucket, key, "", rangeHeader)
}

func (b *FSBackend) GetObjectRangeVersion(ctx context.Context, bucket, key, versionID, rangeHeader string) (io.ReadCloser, ObjectMetadata, int64, int64, error) {
	if err := ensureContext(ctx); err != nil {
		return nil, ObjectMetadata{}, 0, 0, err
	}
	file, meta, err := b.GetObjectVersion(ctx, bucket, key, versionID)
	if err != nil {
		return nil, ObjectMetadata{}, 0, 0, err
	}

	start, end, err := ParseRange(rangeHeader, meta.ContentLength)
	if err != nil {
		_ = file.Close()
		return nil, ObjectMetadata{}, 0, 0, err
	}

	osFile, ok := file.(*os.File)
	if !ok {
		_ = file.Close()
		return nil, ObjectMetadata{}, 0, 0, fmt.Errorf("unexpected reader type")
	}
	if _, err := osFile.Seek(start, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ObjectMetadata{}, 0, 0, fmt.Errorf("seek payload: %w", err)
	}

	length := end - start + 1
	return &rangeReadCloser{Reader: io.LimitReader(osFile, length), closer: osFile}, meta, start, end, nil
}

func (b *FSBackend) HeadObject(ctx context.Context, bucket, key string) (ObjectMetadata, error) {
	return b.HeadObjectVersion(ctx, bucket, key, "")
}

func (b *FSBackend) HeadObjectVersion(ctx context.Context, bucket, key, versionID string) (ObjectMetadata, error) {
	b.mutationMu.RLock()
	defer b.mutationMu.RUnlock()
	return b.headObjectVersionUnlocked(ctx, bucket, key, versionID)
}

func (b *FSBackend) headObjectVersionUnlocked(ctx context.Context, bucket, key, versionID string) (ObjectMetadata, error) {
	if err := ensureContext(ctx); err != nil {
		return ObjectMetadata{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return ObjectMetadata{}, err
	}
	path := b.metaPath(bucket, key)
	if versionID != "" {
		if !isValidVersionID(versionID) {
			return ObjectMetadata{}, ErrInvalidVersionID
		}
		path = b.objectVersionMetaPath(bucket, key, versionID)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if versionID != "" {
				return ObjectMetadata{}, ErrNoSuchVersion
			}
			return ObjectMetadata{}, ErrNoSuchKey
		}
		return ObjectMetadata{}, fmt.Errorf("read metadata: %w", err)
	}

	var metaRecord metadataOnDisk
	if err := json.Unmarshal(bytes, &metaRecord); err != nil {
		return ObjectMetadata{}, fmt.Errorf("decode metadata: %w", err)
	}
	if versionID == "" && metaRecord.DeleteMarker {
		return ObjectMetadata{}, ErrNoSuchKey
	}

	return ObjectMetadata{
		ContentType:   metaRecord.ContentType,
		ContentLength: metaRecord.ContentLength,
		ETag:          metaRecord.ETag,
		LastModified:  metaRecord.LastModified,
		VersionID:     metaRecord.VersionID,
		DeleteMarker:  metaRecord.DeleteMarker,
		UserMetadata:  cloneMap(metaRecord.UserMetadata),
		ObjectTags:    cloneMap(metaRecord.ObjectTags),
	}, nil
}

func (b *FSBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	_, err := b.DeleteObjectVersion(ctx, bucket, key, "")
	return err
}

func (b *FSBackend) DeleteObjectVersion(ctx context.Context, bucket, key, versionID string) (DeleteObjectResult, error) {
	if err := ensureContext(ctx); err != nil {
		return DeleteObjectResult{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return DeleteObjectResult{}, err
	}
	b.mutationMu.Lock()
	defer b.mutationMu.Unlock()

	if versionID != "" {
		if !isValidVersionID(versionID) {
			return DeleteObjectResult{}, ErrInvalidVersionID
		}
		meta, err := b.readObjectVersionMeta(bucket, key, versionID)
		if err != nil {
			return DeleteObjectResult{}, err
		}
		_ = os.Remove(b.objectVersionPath(bucket, key, versionID))
		_ = os.Remove(b.objectVersionMetaPath(bucket, key, versionID))
		current, curErr := b.headObjectVersionUnlocked(ctx, bucket, key, "")
		if curErr == nil && current.VersionID == versionID {
			if restoreErr := b.restoreCurrentFromLatestVersion(ctx, bucket, key); restoreErr != nil {
				return DeleteObjectResult{}, restoreErr
			}
		}
		return DeleteObjectResult{VersionID: versionID, DeleteMarker: meta.DeleteMarker}, nil
	}
	status, err := b.GetBucketVersioning(ctx, bucket)
	if err != nil {
		return DeleteObjectResult{}, err
	}
	if status == BucketVersioningEnabled || status == BucketVersioningSuspended {
		version, genErr := b.nextVersionID(bucket, key)
		if genErr != nil {
			return DeleteObjectResult{}, genErr
		}
		now := time.Now().UTC()
		marker := metadataOnDisk{
			Key:          key,
			LastModified: now,
			VersionID:    version,
			DeleteMarker: true,
			UserMetadata: map[string]string{},
		}
		if err := b.writeVersionMeta(bucket, key, version, marker); err != nil {
			return DeleteObjectResult{}, err
		}
		if err := b.writeCurrentMeta(bucket, key, marker); err != nil {
			return DeleteObjectResult{}, err
		}
		_ = os.Remove(b.objectPath(bucket, key))
		return DeleteObjectResult{VersionID: version, DeleteMarker: true}, nil
	}
	_ = os.Remove(b.objectPath(bucket, key))
	_ = os.Remove(b.metaPath(bucket, key))
	_ = os.Remove(b.objectVersionPath(bucket, key, nullVersionID))
	_ = os.Remove(b.objectVersionMetaPath(bucket, key, nullVersionID))
	return DeleteObjectResult{}, nil
}

func (b *FSBackend) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) (ObjectInfo, error) {
	if err := ensureContext(ctx); err != nil {
		return ObjectInfo{}, err
	}
	if err := b.HeadBucket(ctx, dstBucket); err != nil {
		return ObjectInfo{}, err
	}
	if dstKey == "" {
		return ObjectInfo{}, ErrNoSuchKey
	}
	// Hold the write lock across both the source read and the destination write
	// to prevent a concurrent delete of the source between the two operations.
	b.mutationMu.Lock()
	defer b.mutationMu.Unlock()
	rc, srcMeta, err := b.getObjectVersionUnlocked(ctx, srcBucket, srcKey, "")
	if err != nil {
		return ObjectInfo{}, err
	}
	defer rc.Close()
	return b.putObjectUnderLock(ctx, dstBucket, dstKey, rc, srcMeta)
}

func (b *FSBackend) ListObjectsV2(ctx context.Context, bucket string, opts ListObjectsOptions) (ListObjectsResult, error) {
	// NOTE: This implementation loads all object metadata into memory before applying
	// pagination. This is acceptable for single-node, small-to-medium deployments but
	// will cause high memory usage and latency for buckets containing millions of objects.
	// A future improvement would maintain a sorted on-disk index for O(log n) scans.
	if err := ensureContext(ctx); err != nil {
		return ListObjectsResult{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return ListObjectsResult{}, err
	}

	metaDir := filepath.Join(b.bucketDir(bucket), "meta")
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		return ListObjectsResult{}, fmt.Errorf("read metadata dir: %w", err)
	}

	objects := make([]ObjectInfo, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return ListObjectsResult{}, err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		metaPath := filepath.Join(metaDir, entry.Name())
		bytes, err := os.ReadFile(metaPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return ListObjectsResult{}, fmt.Errorf("read object metadata: %w", err)
		}
		var m metadataOnDisk
		if err := json.Unmarshal(bytes, &m); err != nil {
			// Metadata may be concurrently replaced; skip files that vanish between
			// directory scan and read/decode during high-churn listings.
			if len(bytes) == 0 {
				continue
			}
			return ListObjectsResult{}, fmt.Errorf("decode object metadata: %w", err)
		}
		if m.DeleteMarker {
			continue
		}
		if opts.Prefix != "" && !strings.HasPrefix(m.Key, opts.Prefix) {
			continue
		}
		objects = append(objects, ObjectInfo{
			Bucket:    bucket,
			Key:       m.Key,
			Size:      m.ContentLength,
			ETag:      m.ETag,
			Modified:  m.LastModified,
			VersionID: m.VersionID,
		})
	}

	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })

	startIdx := 0
	if opts.ContinuationToken != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(opts.ContinuationToken)
		if err != nil {
			return ListObjectsResult{}, fmt.Errorf("%w: continuation-token", ErrInvalidRequest)
		}
		marker := string(decoded)
		for i := range objects {
			if objects[i].Key > marker {
				startIdx = i
				break
			}
			startIdx = len(objects)
		}
	} else if opts.StartAfter != "" {
		for i := range objects {
			if objects[i].Key > opts.StartAfter {
				startIdx = i
				break
			}
			startIdx = len(objects)
		}
	}

	maxKeys := opts.MaxKeys
	if maxKeys < 0 {
		maxKeys = 1000
	}
	if maxKeys == 0 {
		return ListObjectsResult{IsTruncated: len(objects[startIdx:]) > 0}, nil
	}

	result := ListObjectsResult{}
	prefixes := make(map[string]struct{})
	count := 0
	var lastKey string

	for i := startIdx; i < len(objects); i++ {
		if err := ctx.Err(); err != nil {
			return ListObjectsResult{}, err
		}
		obj := objects[i]
		if opts.Delimiter != "" {
			remainder := strings.TrimPrefix(obj.Key, opts.Prefix)
			if idx := strings.Index(remainder, opts.Delimiter); idx >= 0 {
				prefix := opts.Prefix + remainder[:idx+len(opts.Delimiter)]
				if _, exists := prefixes[prefix]; !exists {
					if count >= maxKeys {
						result.IsTruncated = true
						break
					}
					prefixes[prefix] = struct{}{}
					result.CommonPrefixes = append(result.CommonPrefixes, prefix)
					count++
				}
				lastKey = obj.Key
				if count >= maxKeys {
					result.IsTruncated = i < len(objects)-1
					break
				}
				continue
			}
		}
		if count >= maxKeys {
			result.IsTruncated = true
			break
		}
		result.Objects = append(result.Objects, obj)
		count++
		lastKey = obj.Key
		if count >= maxKeys {
			result.IsTruncated = i < len(objects)-1
			break
		}
	}

	if result.IsTruncated {
		result.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(lastKey))
	}

	return result, nil
}

func (b *FSBackend) ListObjectVersions(ctx context.Context, bucket string, opts ListObjectVersionsOptions) (ListObjectVersionsResult, error) {
	// NOTE: This implementation loads all object version metadata into memory before applying
	// pagination. This is acceptable for single-node, small-to-medium deployments but
	// will cause high memory usage and latency for buckets containing millions of objects.
	// A future improvement would maintain a sorted on-disk index for O(log n) scans.
	if err := ensureContext(ctx); err != nil {
		return ListObjectVersionsResult{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return ListObjectVersionsResult{}, err
	}
	entries, err := os.ReadDir(b.objectVersionsRoot(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return ListObjectVersionsResult{}, nil
		}
		return ListObjectVersionsResult{}, fmt.Errorf("read versions root: %w", err)
	}

	all := make([]ObjectVersionInfo, 0, len(entries))
	for _, keyDir := range entries {
		if err := ctx.Err(); err != nil {
			return ListObjectVersionsResult{}, err
		}
		if !keyDir.IsDir() {
			continue
		}
		key, decErr := DecodeKey(keyDir.Name())
		if decErr != nil {
			continue
		}
		if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
			continue
		}
		versionFiles, readErr := os.ReadDir(filepath.Join(b.objectVersionsRoot(bucket), keyDir.Name()))
		if readErr != nil {
			return ListObjectVersionsResult{}, fmt.Errorf("read key version dir: %w", readErr)
		}
		keyVersions := make([]ObjectVersionInfo, 0, len(versionFiles))
		for _, vf := range versionFiles {
			if vf.IsDir() || !strings.HasSuffix(vf.Name(), ".json") {
				continue
			}
			versionIDEnc := strings.TrimSuffix(vf.Name(), ".json")
			versionID, decVersionErr := DecodeKey(versionIDEnc)
			if decVersionErr != nil {
				continue
			}
			meta, metaErr := b.readObjectVersionMeta(bucket, key, versionID)
			if metaErr != nil {
				continue
			}
			keyVersions = append(keyVersions, ObjectVersionInfo{
				Key:          key,
				VersionID:    versionID,
				IsDeleteMark: meta.DeleteMarker,
				Size:         meta.ContentLength,
				ETag:         meta.ETag,
				LastModified: meta.LastModified.UTC(),
			})
		}
		sort.Slice(keyVersions, func(i, j int) bool {
			if keyVersions[i].LastModified.Equal(keyVersions[j].LastModified) {
				return keyVersions[i].VersionID > keyVersions[j].VersionID
			}
			return keyVersions[i].LastModified.After(keyVersions[j].LastModified)
		})
		if len(keyVersions) > 0 {
			keyVersions[0].IsLatest = true
		}
		all = append(all, keyVersions...)
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Key == all[j].Key {
			if all[i].LastModified.Equal(all[j].LastModified) {
				return all[i].VersionID > all[j].VersionID
			}
			return all[i].LastModified.After(all[j].LastModified)
		}
		return all[i].Key < all[j].Key
	})

	start := 0
	if opts.KeyMarker != "" {
		start = len(all)
		for i, v := range all {
			if v.Key < opts.KeyMarker {
				continue
			}
			if v.Key > opts.KeyMarker {
				start = i
				break
			}
			if opts.VersionIDMarker == "" {
				continue
			}
			if v.VersionID <= opts.VersionIDMarker {
				continue
			}
			start = i
			break
		}
	}
	maxKeys := opts.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 1000
	}
	end := start + maxKeys
	if end > len(all) {
		end = len(all)
	}
	out := ListObjectVersionsResult{Versions: append([]ObjectVersionInfo(nil), all[start:end]...)}
	if end < len(all) && len(out.Versions) > 0 {
		out.IsTruncated = true
		last := out.Versions[len(out.Versions)-1]
		out.NextKeyMarker = last.Key
		out.NextVersionIDMarker = last.VersionID
	}
	return out, nil
}

func (b *FSBackend) bucketDir(bucket string) string {
	return filepath.Join(b.rootDir, "buckets", bucket)
}

func (b *FSBackend) objectPath(bucket, key string) string {
	return filepath.Join(b.bucketDir(bucket), "objects", EncodeKey(key)+".bin")
}

func (b *FSBackend) metaPath(bucket, key string) string {
	return filepath.Join(b.bucketDir(bucket), "meta", EncodeKey(key)+".json")
}

func (b *FSBackend) objectVersionsRoot(bucket string) string {
	return filepath.Join(b.bucketDir(bucket), "versions")
}

func (b *FSBackend) objectVersionDir(bucket, key string) string {
	return filepath.Join(b.objectVersionsRoot(bucket), EncodeKey(key))
}

func (b *FSBackend) objectVersionPath(bucket, key, versionID string) string {
	return filepath.Join(b.objectVersionDir(bucket, key), EncodeKey(versionID)+".bin")
}

func (b *FSBackend) objectVersionMetaPath(bucket, key, versionID string) string {
	return filepath.Join(b.objectVersionDir(bucket, key), EncodeKey(versionID)+".json")
}

func (b *FSBackend) bucketMetaPath(bucket string) string {
	return filepath.Join(b.bucketDir(bucket), "bucket.json")
}

func (b *FSBackend) bucketLifecyclePath(bucket string) string {
	return filepath.Join(b.bucketDir(bucket), "bucket.lifecycle.json")
}

func (b *FSBackend) bucketPolicyPath(bucket string) string {
	return filepath.Join(b.bucketDir(bucket), "bucket.policy.json")
}

func (b *FSBackend) readBucketMetadata(bucket string) (bucketMetadataOnDisk, error) {
	path := b.bucketMetaPath(bucket)
	bytes, err := os.ReadFile(path)
	if err == nil {
		var meta bucketMetadataOnDisk
		if unmarshalErr := json.Unmarshal(bytes, &meta); unmarshalErr == nil && !meta.CreationDate.IsZero() {
			return meta, nil
		}
	}

	info, statErr := os.Stat(b.bucketDir(bucket))
	if statErr != nil {
		return bucketMetadataOnDisk{}, fmt.Errorf("stat bucket dir: %w", statErr)
	}
	meta := bucketMetadataOnDisk{CreationDate: info.ModTime().UTC()}
	encoded, marshalErr := json.Marshal(meta)
	if marshalErr == nil {
		slog.Warn("bucket.json missing or corrupt; auto-healing from directory mtime", "bucket", bucket, "path", path)
		_ = writeFileAtomic(path, encoded, 0o644)
	}
	return meta, nil
}

func (b *FSBackend) writeBucketMetadata(bucket string, meta bucketMetadataOnDisk) error {
	encoded, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal bucket metadata: %w", err)
	}
	if err := writeFileAtomic(b.bucketMetaPath(bucket), encoded, 0o644); err != nil {
		return fmt.Errorf("write bucket metadata: %w", err)
	}
	return nil
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func generateVersionID() (string, error) {
	var entropy [16]byte
	if _, err := cryptorand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("read version id entropy: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])
	return fmt.Sprintf("v-%d-%s", time.Now().UTC().UnixNano(), encoded), nil
}

func (b *FSBackend) nextVersionID(bucket, key string) (string, error) {
	for i := 0; i < versionIDMaxAttempts; i++ {
		versionID, err := generateVersionID()
		if err != nil {
			return "", err
		}
		exists, err := b.versionIDExists(bucket, key, versionID)
		if err != nil {
			return "", err
		}
		if !exists {
			return versionID, nil
		}
	}
	return "", fmt.Errorf("allocate unique version id: %w", ErrInvalidRequest)
}

func (b *FSBackend) versionIDExists(bucket, key, versionID string) (bool, error) {
	if _, err := os.Stat(b.objectVersionPath(bucket, key, versionID)); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat version payload: %w", err)
	}
	if _, err := os.Stat(b.objectVersionMetaPath(bucket, key, versionID)); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat version metadata: %w", err)
	}
	return false, nil
}

func isValidVersionID(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	if strings.ContainsAny(value, `/\`) {
		return false
	}
	return filepath.Clean(value) == value
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (b *FSBackend) readObjectVersionMeta(bucket, key, versionID string) (metadataOnDisk, error) {
	bytes, err := os.ReadFile(b.objectVersionMetaPath(bucket, key, versionID))
	if err != nil {
		if os.IsNotExist(err) {
			return metadataOnDisk{}, ErrNoSuchVersion
		}
		return metadataOnDisk{}, fmt.Errorf("read version metadata: %w", err)
	}
	var meta metadataOnDisk
	if err := json.Unmarshal(bytes, &meta); err != nil {
		return metadataOnDisk{}, fmt.Errorf("decode version metadata: %w", err)
	}
	return meta, nil
}

func (b *FSBackend) writeVersionMeta(bucket, key, versionID string, meta metadataOnDisk) error {
	if err := os.MkdirAll(b.objectVersionDir(bucket, key), 0o755); err != nil {
		return fmt.Errorf("ensure version dir: %w", err)
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal version metadata: %w", err)
	}
	if err := writeFileAtomic(b.objectVersionMetaPath(bucket, key, versionID), encoded, 0o644); err != nil {
		return fmt.Errorf("write version metadata: %w", err)
	}
	return nil
}

func (b *FSBackend) writeCurrentMeta(bucket, key string, meta metadataOnDisk) error {
	if err := os.MkdirAll(filepath.Dir(b.metaPath(bucket, key)), 0o755); err != nil {
		return fmt.Errorf("ensure current metadata dir: %w", err)
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal current metadata: %w", err)
	}
	if err := writeFileAtomic(b.metaPath(bucket, key), encoded, 0o644); err != nil {
		return fmt.Errorf("write current metadata: %w", err)
	}
	return nil
}

func (b *FSBackend) ensureLegacyNullVersion(ctx context.Context, bucket, key string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	metaBytes, err := os.ReadFile(b.metaPath(bucket, key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read current metadata: %w", err)
	}
	var meta metadataOnDisk
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil
	}
	if meta.VersionID != "" {
		return nil
	}
	if err := os.MkdirAll(b.objectVersionDir(bucket, key), 0o755); err != nil {
		return fmt.Errorf("ensure legacy version dir: %w", err)
	}
	if _, statErr := os.Stat(b.objectVersionMetaPath(bucket, key, nullVersionID)); statErr == nil {
		return nil
	}
	meta.VersionID = nullVersionID
	if err := b.writeVersionMeta(bucket, key, nullVersionID, meta); err != nil {
		return err
	}
	if err := copyFile(b.objectPath(bucket, key), b.objectVersionPath(bucket, key, nullVersionID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("copy legacy payload to null version: %w", err)
	}
	return b.writeCurrentMeta(bucket, key, meta)
}

func (b *FSBackend) restoreCurrentFromLatestVersion(ctx context.Context, bucket, key string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	dir := b.objectVersionDir(bucket, key)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			_ = os.Remove(b.metaPath(bucket, key))
			_ = os.Remove(b.objectPath(bucket, key))
			return nil
		}
		return fmt.Errorf("read version dir: %w", err)
	}
	metas := make([]metadataOnDisk, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		versionID, decErr := DecodeKey(strings.TrimSuffix(entry.Name(), ".json"))
		if decErr != nil {
			continue
		}
		meta, readErr := b.readObjectVersionMeta(bucket, key, versionID)
		if readErr != nil {
			continue
		}
		metas = append(metas, meta)
	}
	if len(metas) == 0 {
		_ = os.Remove(b.metaPath(bucket, key))
		_ = os.Remove(b.objectPath(bucket, key))
		return nil
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].LastModified.After(metas[j].LastModified) })
	current := metas[0]
	if err := b.writeCurrentMeta(bucket, key, current); err != nil {
		return err
	}
	if current.DeleteMarker {
		_ = os.Remove(b.objectPath(bucket, key))
		return nil
	}
	if current.VersionID == "" {
		return nil
	}
	if err := copyFile(b.objectVersionPath(bucket, key, current.VersionID), b.objectPath(bucket, key)); err != nil {
		return err
	}
	return nil
}

func (b *FSBackend) migrateBucketLegacyObjectsToNullVersions(ctx context.Context, bucket string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(b.bucketDir(bucket), "meta"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read bucket metadata for migration: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		key, decErr := DecodeKey(strings.TrimSuffix(entry.Name(), ".json"))
		if decErr != nil {
			continue
		}
		if err := b.ensureLegacyNullVersion(ctx, bucket, key); err != nil {
			return err
		}
	}
	return nil
}

type rangeReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *rangeReadCloser) Close() error {
	return r.closer.Close()
}

func ensureContext(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "storas-atomic-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
