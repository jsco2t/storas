package storage

import (
	"context"
	"io"
	"time"
)

// ObjectMetadata persists object headers and user metadata alongside payload bytes.
type ObjectMetadata struct {
	ContentType   string
	ContentLength int64
	ETag          string
	LastModified  time.Time
	VersionID     string
	DeleteMarker  bool
	UserMetadata  map[string]string
	ObjectTags    map[string]string
}

// ObjectInfo summarizes a stored object for list/head style operations.
type ObjectInfo struct {
	Bucket       string
	Key          string
	Size         int64
	ETag         string
	Modified     time.Time
	VersionID    string
	DeleteMarker bool
}

type DeleteObjectResult struct {
	VersionID    string
	DeleteMarker bool
}

type BucketInfo struct {
	Name         string
	CreationDate time.Time
}

type BucketVersioningStatus string

const (
	BucketVersioningOff       BucketVersioningStatus = "Off"
	BucketVersioningEnabled   BucketVersioningStatus = "Enabled"
	BucketVersioningSuspended BucketVersioningStatus = "Suspended"
)

type ListObjectsOptions struct {
	Prefix            string
	Delimiter         string
	ContinuationToken string
	StartAfter        string
	MaxKeys           int
}

type LifecycleConfiguration struct {
	Rules []LifecycleRule
}

type LifecycleRule struct {
	ID                        string
	Status                    string
	Prefix                    string
	Tags                      map[string]string
	ObjectSizeGreaterThan     int64
	ObjectSizeLessThan        int64
	ExpirationDays            int
	ExpirationDate            time.Time
	NoncurrentExpirationDays  int
	AbortIncompleteUploadDays int
}

type LifecycleSweepOptions struct {
	MaxActions int
	DryRun     bool
}

type LifecycleRuleResult struct {
	Bucket            string
	RuleID            string
	Action            string
	MatchedCandidates int
	AppliedActions    int
	SkippedByLimit    int
}

type LifecycleMaintenanceResult struct {
	BucketsScanned  int
	RulesEvaluated  int
	ActionsExecuted int
	ActionsDryRun   int
	SkippedByLimit  int
	RuleResults     []LifecycleRuleResult
}

type ListObjectsResult struct {
	Objects               []ObjectInfo
	CommonPrefixes        []string
	IsTruncated           bool
	NextContinuationToken string
}

type ObjectVersionInfo struct {
	Key          string
	VersionID    string
	IsLatest     bool
	IsDeleteMark bool
	Size         int64
	ETag         string
	LastModified time.Time
}

type ListObjectVersionsOptions struct {
	Prefix          string
	KeyMarker       string
	VersionIDMarker string
	MaxKeys         int
}

type ListObjectVersionsResult struct {
	Versions            []ObjectVersionInfo
	IsTruncated         bool
	NextKeyMarker       string
	NextVersionIDMarker string
}

type CompletedPart struct {
	PartNumber int
	ETag       string
}

type MultipartUpload struct {
	Key       string
	UploadID  string
	Initiated time.Time
}

type MultipartUploadListOptions struct {
	Prefix            string
	KeyMarker         string
	UploadIDMarker    string
	HasUploadIDMarker bool
	MaxUploads        int
}

type MultipartUploadListResult struct {
	Uploads            []MultipartUpload
	IsTruncated        bool
	NextKeyMarker      string
	NextUploadIDMarker string
}

type MultipartPartInfo struct {
	PartNumber   int
	Size         int64
	ETag         string
	LastModified time.Time
}

type ListPartsOptions struct {
	PartNumberMarker int
	MaxParts         int
}

type ListPartsResult struct {
	Parts                []MultipartPartInfo
	IsTruncated          bool
	NextPartNumberMarker int
}

// Backend defines filesystem-backed bucket and object primitives used by the API layer.
type Backend interface {
	CreateBucket(ctx context.Context, bucket string) error
	DeleteBucket(ctx context.Context, bucket string) error
	HeadBucket(ctx context.Context, bucket string) error
	ListBuckets(ctx context.Context) ([]string, error)
	GetBucketInfo(ctx context.Context, bucket string) (BucketInfo, error)
	GetBucketVersioning(ctx context.Context, bucket string) (BucketVersioningStatus, error)
	PutBucketVersioning(ctx context.Context, bucket string, status BucketVersioningStatus) error
	GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error)
	PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error
	DeleteBucketPolicy(ctx context.Context, bucket string) error
	GetBucketLifecycle(ctx context.Context, bucket string) (LifecycleConfiguration, error)
	PutBucketLifecycle(ctx context.Context, bucket string, cfg LifecycleConfiguration) error
	DeleteBucketLifecycle(ctx context.Context, bucket string) error

	PutObject(ctx context.Context, bucket, key string, body io.Reader, metadata ObjectMetadata) (ObjectInfo, error)
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, ObjectMetadata, error)
	GetObjectRange(ctx context.Context, bucket, key, rangeHeader string) (io.ReadCloser, ObjectMetadata, int64, int64, error)
	HeadObject(ctx context.Context, bucket, key string) (ObjectMetadata, error)
	GetObjectVersion(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, ObjectMetadata, error)
	GetObjectRangeVersion(ctx context.Context, bucket, key, versionID, rangeHeader string) (io.ReadCloser, ObjectMetadata, int64, int64, error)
	HeadObjectVersion(ctx context.Context, bucket, key, versionID string) (ObjectMetadata, error)
	DeleteObject(ctx context.Context, bucket, key string) error
	DeleteObjectVersion(ctx context.Context, bucket, key, versionID string) (DeleteObjectResult, error)
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) (ObjectInfo, error)
	ListObjectsV2(ctx context.Context, bucket string, opts ListObjectsOptions) (ListObjectsResult, error)
	ListObjectVersions(ctx context.Context, bucket string, opts ListObjectVersionsOptions) (ListObjectVersionsResult, error)
	CreateMultipartUpload(ctx context.Context, bucket, key string, metadata ObjectMetadata) (string, error)
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, body io.Reader) (MultipartPartInfo, error)
	CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) (ObjectInfo, error)
	AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error
	ListMultipartUploads(ctx context.Context, bucket string, opts MultipartUploadListOptions) (MultipartUploadListResult, error)
	ListParts(ctx context.Context, bucket, key, uploadID string, opts ListPartsOptions) (ListPartsResult, error)
}
