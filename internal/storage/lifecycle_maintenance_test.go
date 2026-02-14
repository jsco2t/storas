package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMatchesLifecyclePrefix(t *testing.T) {
	t.Parallel()
	if !matchesLifecyclePrefix("", "any/key") {
		t.Fatal("expected empty prefix to match")
	}
	if !matchesLifecyclePrefix("logs/", "logs/2026/file.txt") {
		t.Fatal("expected prefixed key to match")
	}
	if matchesLifecyclePrefix("logs/", "images/a.png") {
		t.Fatal("expected non-matching key")
	}
}

func TestMatchesLifecycleRuleWithTags(t *testing.T) {
	t.Parallel()
	rule := LifecycleRule{Prefix: "logs/", Tags: map[string]string{"env": "prod"}}
	if !matchesLifecycleRule(rule, "logs/a.txt", map[string]string{"env": "prod", "team": "ops"}, 10) {
		t.Fatal("expected matching prefix/tags to pass")
	}
	if matchesLifecycleRule(rule, "logs/a.txt", map[string]string{"env": "dev"}, 10) {
		t.Fatal("expected mismatched tag to fail")
	}
	if matchesLifecycleRule(rule, "images/a.txt", map[string]string{"env": "prod"}, 10) {
		t.Fatal("expected mismatched prefix to fail")
	}
}

func TestMatchesLifecycleRuleWithSizePredicates(t *testing.T) {
	t.Parallel()
	rule := LifecycleRule{ObjectSizeGreaterThan: 2, ObjectSizeLessThan: 8}
	if !matchesLifecycleRule(rule, "logs/a.txt", nil, 4) {
		t.Fatal("expected size within predicate bounds to match")
	}
	if matchesLifecycleRule(rule, "logs/a.txt", nil, 2) {
		t.Fatal("expected object-size-greater-than to be exclusive")
	}
	if matchesLifecycleRule(rule, "logs/a.txt", nil, 8) {
		t.Fatal("expected object-size-less-than to be exclusive")
	}
	if !matchesLifecycleRule(rule, "logs/a.txt", nil, -1) {
		t.Fatal("expected unknown size to skip size predicates")
	}
}

func TestSweepLifecycleExpiresCurrentObjectsWithLimit(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-current"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketLifecycle(ctx, "life-current", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:             "expire-current",
		Status:         "Enabled",
		Prefix:         "logs/",
		ExpirationDays: 1,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-current", "logs/one.txt", strings.NewReader("one"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject one error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-current", "logs/two.txt", strings.NewReader("two"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject two error: %v", err)
	}

	now := time.Now().UTC().Add(48 * time.Hour)
	res, err := backend.SweepLifecycle(ctx, now, LifecycleSweepOptions{MaxActions: 1})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}
	if res.ActionsExecuted != 1 {
		t.Fatalf("expected one executed action, got %d", res.ActionsExecuted)
	}
	if res.SkippedByLimit == 0 {
		t.Fatal("expected skip by limit")
	}

	listed, err := backend.ListObjectsV2(ctx, "life-current", ListObjectsOptions{MaxKeys: 1000, Prefix: "logs/"})
	if err != nil {
		t.Fatalf("ListObjectsV2 error: %v", err)
	}
	if len(listed.Objects) != 1 {
		t.Fatalf("expected one remaining object, got %d", len(listed.Objects))
	}
}

func TestSweepLifecycleExpiresNoncurrentVersions(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-version"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketVersioning(ctx, "life-version", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning error: %v", err)
	}
	if err := backend.PutBucketLifecycle(ctx, "life-version", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:                       "expire-noncurrent",
		Status:                   "Enabled",
		NoncurrentExpirationDays: 1,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-version", "key.txt", strings.NewReader("v1"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject v1 error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-version", "key.txt", strings.NewReader("v2"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject v2 error: %v", err)
	}

	res, err := backend.SweepLifecycle(ctx, time.Now().UTC().Add(48*time.Hour), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}
	if res.ActionsExecuted == 0 {
		t.Fatal("expected noncurrent version expiration action")
	}

	versions, err := backend.ListObjectVersions(ctx, "life-version", ListObjectVersionsOptions{MaxKeys: 1000})
	if err != nil {
		t.Fatalf("ListObjectVersions error: %v", err)
	}
	if len(versions.Versions) != 1 {
		t.Fatalf("expected one version after sweep, got %d", len(versions.Versions))
	}
	if !versions.Versions[0].IsLatest {
		t.Fatal("expected remaining version to be latest")
	}
}

func TestSweepLifecycleAbortsIncompleteMultipartAndSupportsDryRun(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-multipart"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketLifecycle(ctx, "life-multipart", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:                        "abort-stale",
		Status:                    "Enabled",
		AbortIncompleteUploadDays: 1,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	uploadID, err := backend.CreateMultipartUpload(ctx, "life-multipart", "obj.txt", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}

	dryRun, err := backend.SweepLifecycle(ctx, time.Now().UTC().Add(48*time.Hour), LifecycleSweepOptions{DryRun: true})
	if err != nil {
		t.Fatalf("SweepLifecycle dry-run error: %v", err)
	}
	if dryRun.ActionsDryRun == 0 {
		t.Fatal("expected dry-run action count")
	}
	uploads, err := backend.ListMultipartUploads(ctx, "life-multipart", MultipartUploadListOptions{MaxUploads: 1000})
	if err != nil {
		t.Fatalf("ListMultipartUploads error: %v", err)
	}
	if len(uploads.Uploads) != 1 {
		t.Fatalf("expected multipart upload preserved in dry-run, got %d", len(uploads.Uploads))
	}
	if uploads.Uploads[0].UploadID != uploadID {
		t.Fatalf("expected upload %q to remain, got %q", uploadID, uploads.Uploads[0].UploadID)
	}

	applied, err := backend.SweepLifecycle(ctx, time.Now().UTC().Add(48*time.Hour), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle apply error: %v", err)
	}
	if applied.ActionsExecuted == 0 {
		t.Fatal("expected multipart abort action")
	}
	uploadsAfter, err := backend.ListMultipartUploads(ctx, "life-multipart", MultipartUploadListOptions{MaxUploads: 1000})
	if err != nil {
		t.Fatalf("ListMultipartUploads after apply error: %v", err)
	}
	if len(uploadsAfter.Uploads) != 0 {
		t.Fatalf("expected no uploads after apply, got %d", len(uploadsAfter.Uploads))
	}
}

func TestSweepLifecycleTagFilterExpiresOnlyMatchingObjects(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-tag"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketLifecycle(ctx, "life-tag", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:             "expire-prod",
		Status:         "Enabled",
		Prefix:         "logs/",
		Tags:           map[string]string{"env": "prod"},
		ExpirationDays: 1,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-tag", "logs/prod.txt", strings.NewReader("prod"), ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}}); err != nil {
		t.Fatalf("PutObject prod error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-tag", "logs/dev.txt", strings.NewReader("dev"), ObjectMetadata{ObjectTags: map[string]string{"env": "dev"}}); err != nil {
		t.Fatalf("PutObject dev error: %v", err)
	}

	res, err := backend.SweepLifecycle(ctx, time.Now().UTC().Add(48*time.Hour), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}
	if res.ActionsExecuted == 0 {
		t.Fatal("expected at least one lifecycle action")
	}

	if _, err := backend.HeadObject(ctx, "life-tag", "logs/prod.txt"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("expected prod object to expire, got %v", err)
	}
	if _, err := backend.HeadObject(ctx, "life-tag", "logs/dev.txt"); err != nil {
		t.Fatalf("expected dev object to remain, got %v", err)
	}
}

func TestSweepLifecycleTagFilterAbortsMatchingMultipartOnly(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-multipart-tag"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketLifecycle(ctx, "life-multipart-tag", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:                        "abort-prod",
		Status:                    "Enabled",
		Tags:                      map[string]string{"env": "prod"},
		AbortIncompleteUploadDays: 1,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	if _, err := backend.CreateMultipartUpload(ctx, "life-multipart-tag", "prod.txt", ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}}); err != nil {
		t.Fatalf("CreateMultipartUpload prod error: %v", err)
	}
	if _, err := backend.CreateMultipartUpload(ctx, "life-multipart-tag", "dev.txt", ObjectMetadata{ObjectTags: map[string]string{"env": "dev"}}); err != nil {
		t.Fatalf("CreateMultipartUpload dev error: %v", err)
	}

	_, err = backend.SweepLifecycle(ctx, time.Now().UTC().Add(48*time.Hour), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}

	uploads, err := backend.ListMultipartUploads(ctx, "life-multipart-tag", MultipartUploadListOptions{MaxUploads: 1000})
	if err != nil {
		t.Fatalf("ListMultipartUploads error: %v", err)
	}
	if len(uploads.Uploads) != 1 || uploads.Uploads[0].Key != "dev.txt" {
		t.Fatalf("expected only dev upload to remain, got %+v", uploads.Uploads)
	}
}

func TestSweepLifecycleAdvancedCombinationFiltersCurrentAndNoncurrent(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-advanced"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	if err := backend.PutBucketVersioning(ctx, "life-advanced", BucketVersioningEnabled); err != nil {
		t.Fatalf("PutBucketVersioning error: %v", err)
	}
	if err := backend.PutBucketLifecycle(ctx, "life-advanced", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:                       "advanced-rule",
		Status:                   "Enabled",
		Prefix:                   "logs/",
		Tags:                     map[string]string{"env": "prod"},
		ObjectSizeGreaterThan:    3,
		ObjectSizeLessThan:       8,
		ExpirationDays:           1,
		NoncurrentExpirationDays: 1,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-advanced", "logs/match.txt", strings.NewReader("v111"), ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}}); err != nil {
		t.Fatalf("PutObject logs/match v1 error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-advanced", "logs/match.txt", strings.NewReader("v222"), ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}}); err != nil {
		t.Fatalf("PutObject logs/match v2 error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-advanced", "logs/too-small.txt", strings.NewReader("a"), ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}}); err != nil {
		t.Fatalf("PutObject logs/too-small error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-advanced", "logs/wrong-tag.txt", strings.NewReader("v333"), ObjectMetadata{ObjectTags: map[string]string{"env": "dev"}}); err != nil {
		t.Fatalf("PutObject logs/wrong-tag error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-advanced", "images/match.txt", strings.NewReader("v444"), ObjectMetadata{ObjectTags: map[string]string{"env": "prod"}}); err != nil {
		t.Fatalf("PutObject images/match error: %v", err)
	}

	res, err := backend.SweepLifecycle(ctx, time.Now().UTC().Add(48*time.Hour), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}
	if res.ActionsExecuted < 2 {
		t.Fatalf("expected at least two actions, got %d", res.ActionsExecuted)
	}
	if _, err := backend.HeadObject(ctx, "life-advanced", "logs/match.txt"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("expected current logs/match to expire, got %v", err)
	}
	versions, err := backend.ListObjectVersions(ctx, "life-advanced", ListObjectVersionsOptions{Prefix: "logs/match.txt", MaxKeys: 1000})
	if err != nil {
		t.Fatalf("ListObjectVersions error: %v", err)
	}
	for _, version := range versions.Versions {
		if !version.IsLatest {
			t.Fatalf("expected noncurrent versions to expire, got %+v", versions.Versions)
		}
	}
	if _, err := backend.HeadObject(ctx, "life-advanced", "logs/too-small.txt"); err != nil {
		t.Fatalf("expected logs/too-small to remain, got %v", err)
	}
	if _, err := backend.HeadObject(ctx, "life-advanced", "logs/wrong-tag.txt"); err != nil {
		t.Fatalf("expected logs/wrong-tag to remain, got %v", err)
	}
	if _, err := backend.HeadObject(ctx, "life-advanced", "images/match.txt"); err != nil {
		t.Fatalf("expected images/match to remain, got %v", err)
	}
}

func TestSweepLifecycleExpirationDate(t *testing.T) {
	t.Parallel()
	backend, err := NewFSBackend(t.TempDir(), defaultMaxObjectSize)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	ctx := context.Background()
	if err := backend.CreateBucket(ctx, "life-date"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}
	expirationDate := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	if err := backend.PutBucketLifecycle(ctx, "life-date", LifecycleConfiguration{Rules: []LifecycleRule{{
		ID:             "date-expiry",
		Status:         "Enabled",
		Prefix:         "logs/",
		ExpirationDate: expirationDate,
	}}}); err != nil {
		t.Fatalf("PutBucketLifecycle error: %v", err)
	}
	if _, err := backend.PutObject(ctx, "life-date", "logs/by-date.txt", strings.NewReader("value"), ObjectMetadata{}); err != nil {
		t.Fatalf("PutObject error: %v", err)
	}

	before, err := backend.SweepLifecycle(ctx, expirationDate.Add(-time.Minute), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle before date error: %v", err)
	}
	if before.ActionsExecuted != 0 {
		t.Fatalf("expected zero actions before date, got %d", before.ActionsExecuted)
	}
	if _, err := backend.HeadObject(ctx, "life-date", "logs/by-date.txt"); err != nil {
		t.Fatalf("expected object to remain before date, got %v", err)
	}

	after, err := backend.SweepLifecycle(ctx, expirationDate.Add(time.Minute), LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle after date error: %v", err)
	}
	if after.ActionsExecuted == 0 {
		t.Fatal("expected action execution after date threshold")
	}
	if _, err := backend.HeadObject(ctx, "life-date", "logs/by-date.txt"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("expected object to expire after date, got %v", err)
	}
}
