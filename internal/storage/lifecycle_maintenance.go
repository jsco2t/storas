package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	lifecycleActionExpireCurrent    = "expire-current"
	lifecycleActionExpireNoncurrent = "expire-noncurrent"
	lifecycleActionAbortMultipart   = "abort-multipart"
)

type lifecycleActionBudget struct {
	maxActions int
	dryRun     bool
	used       int
	executed   int
	dryRunHits int
	skipped    int
}

func (b *FSBackend) SweepLifecycle(ctx context.Context, now time.Time, opts LifecycleSweepOptions) (LifecycleMaintenanceResult, error) {
	if opts.MaxActions < 0 {
		return LifecycleMaintenanceResult{}, ErrInvalidRequest
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	buckets, err := b.ListBuckets(ctx)
	if err != nil {
		return LifecycleMaintenanceResult{}, err
	}

	result := LifecycleMaintenanceResult{}
	budget := &lifecycleActionBudget{maxActions: opts.MaxActions, dryRun: opts.DryRun}
	processedVersions := make(map[string]struct{})
	processedMultipart := make(map[string]struct{})
	processedCurrent := make(map[string]struct{})
	var errs []error

	for _, bucket := range buckets {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.BucketsScanned++

		cfg, cfgErr := b.GetBucketLifecycle(ctx, bucket)
		if cfgErr != nil {
			if errors.Is(cfgErr, ErrNoSuchLifecycleConfiguration) {
				continue
			}
			errs = append(errs, fmt.Errorf("load lifecycle config for bucket %q: %w", bucket, cfgErr))
			continue
		}
		for i, rule := range cfg.Rules {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if rule.Status != "Enabled" {
				continue
			}
			result.RulesEvaluated++
			ruleID := strings.TrimSpace(rule.ID)
			if ruleID == "" {
				ruleID = fmt.Sprintf("rule-%d", i+1)
			}
			if rule.ExpirationDays > 0 || !rule.ExpirationDate.IsZero() {
				rr, actionErr := b.expireCurrentVersions(ctx, now, bucket, ruleID, rule, rule.ExpirationDays, budget, processedCurrent)
				result.RuleResults = append(result.RuleResults, rr)
				if actionErr != nil {
					errs = append(errs, actionErr)
				}
			}
			if rule.NoncurrentExpirationDays > 0 {
				rr, actionErr := b.expireNoncurrentVersions(ctx, now, bucket, ruleID, rule, rule.NoncurrentExpirationDays, budget, processedVersions)
				result.RuleResults = append(result.RuleResults, rr)
				if actionErr != nil {
					errs = append(errs, actionErr)
				}
			}
			if rule.AbortIncompleteUploadDays > 0 {
				rr, actionErr := b.abortIncompleteMultipart(ctx, now, bucket, ruleID, rule, rule.AbortIncompleteUploadDays, budget, processedMultipart)
				result.RuleResults = append(result.RuleResults, rr)
				if actionErr != nil {
					errs = append(errs, actionErr)
				}
			}
		}
	}

	result.ActionsExecuted = budget.executed
	result.ActionsDryRun = budget.dryRunHits
	result.SkippedByLimit = budget.skipped
	return result, errors.Join(errs...)
}

func (b *FSBackend) expireCurrentVersions(
	ctx context.Context,
	now time.Time,
	bucket, ruleID string,
	rule LifecycleRule,
	days int,
	budget *lifecycleActionBudget,
	processed map[string]struct{},
) (LifecycleRuleResult, error) {
	res := LifecycleRuleResult{Bucket: bucket, RuleID: ruleID, Action: lifecycleActionExpireCurrent}
	if days <= 0 && rule.ExpirationDate.IsZero() {
		return res, nil
	}

	entries, err := os.ReadDir(filepath.Join(b.bucketDir(bucket), "meta"))
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("list current object metadata for bucket %q: %w", bucket, err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		key, decErr := DecodeKey(strings.TrimSuffix(entry.Name(), ".json"))
		if decErr != nil || !matchesLifecyclePrefix(rule.Prefix, key) {
			continue
		}
		identifier := bucket + "/" + key
		if _, seen := processed[identifier]; seen {
			continue
		}
		meta, metaErr := b.HeadObject(ctx, bucket, key)
		if metaErr != nil {
			if errors.Is(metaErr, ErrNoSuchKey) {
				continue
			}
			return res, fmt.Errorf("head current object %q/%q: %w", bucket, key, metaErr)
		}
		if !matchesLifecycleRule(rule, key, meta.ObjectTags, meta.ContentLength) {
			continue
		}
		if !ruleMatchesCurrentExpiration(now, meta.LastModified, rule, days) {
			continue
		}
		res.MatchedCandidates++
		applied, applyErr := budget.apply(func() error {
			if err := b.DeleteObject(ctx, bucket, key); err != nil {
				if errors.Is(err, ErrNoSuchKey) {
					return nil
				}
				return err
			}
			return nil
		})
		if !applied {
			res.SkippedByLimit++
			continue
		}
		if applyErr != nil {
			return res, fmt.Errorf("expire current object %q/%q: %w", bucket, key, applyErr)
		}
		res.AppliedActions++
		processed[identifier] = struct{}{}
	}
	return res, nil
}

func (b *FSBackend) expireNoncurrentVersions(
	ctx context.Context,
	now time.Time,
	bucket, ruleID string,
	rule LifecycleRule,
	days int,
	budget *lifecycleActionBudget,
	processed map[string]struct{},
) (LifecycleRuleResult, error) {
	res := LifecycleRuleResult{Bucket: bucket, RuleID: ruleID, Action: lifecycleActionExpireNoncurrent}
	if days <= 0 {
		return res, nil
	}

	keyEntries, err := os.ReadDir(b.objectVersionsRoot(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("list object versions root for bucket %q: %w", bucket, err)
	}
	sort.Slice(keyEntries, func(i, j int) bool {
		return keyEntries[i].Name() < keyEntries[j].Name()
	})

	for _, keyDir := range keyEntries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !keyDir.IsDir() {
			continue
		}
		key, decErr := DecodeKey(keyDir.Name())
		if decErr != nil || !matchesLifecyclePrefix(rule.Prefix, key) {
			continue
		}
		versions, versionErr := b.listKeyVersions(bucket, key)
		if versionErr != nil {
			return res, versionErr
		}
		for idx, version := range versions {
			if idx == 0 || version.meta.DeleteMarker {
				continue
			}
			identifier := bucket + "/" + key + "#" + version.id
			if _, seen := processed[identifier]; seen {
				continue
			}
			if !matchesLifecycleRule(rule, key, version.meta.ObjectTags, version.meta.ContentLength) {
				continue
			}
			if ageDays(now, version.meta.LastModified) < days {
				continue
			}
			res.MatchedCandidates++
			versionID := version.id
			applied, applyErr := budget.apply(func() error {
				_, err := b.DeleteObjectVersion(ctx, bucket, key, versionID)
				if err != nil {
					if errors.Is(err, ErrNoSuchVersion) {
						return nil
					}
					return err
				}
				return nil
			})
			if !applied {
				res.SkippedByLimit++
				continue
			}
			if applyErr != nil {
				return res, fmt.Errorf("expire noncurrent version %q/%q/%q: %w", bucket, key, versionID, applyErr)
			}
			res.AppliedActions++
			processed[identifier] = struct{}{}
		}
	}
	return res, nil
}

func (b *FSBackend) abortIncompleteMultipart(
	ctx context.Context,
	now time.Time,
	bucket, ruleID string,
	rule LifecycleRule,
	days int,
	budget *lifecycleActionBudget,
	processed map[string]struct{},
) (LifecycleRuleResult, error) {
	res := LifecycleRuleResult{Bucket: bucket, RuleID: ruleID, Action: lifecycleActionAbortMultipart}
	if days <= 0 {
		return res, nil
	}

	opts := MultipartUploadListOptions{MaxUploads: 1000}
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		list, err := b.ListMultipartUploads(ctx, bucket, opts)
		if err != nil {
			return res, fmt.Errorf("list multipart uploads for bucket %q: %w", bucket, err)
		}
		for _, up := range list.Uploads {
			if !matchesLifecyclePrefix(rule.Prefix, up.Key) {
				continue
			}
			manifest, manifestErr := b.readMultipartManifest(ctx, bucket, up.UploadID)
			if manifestErr != nil {
				if errors.Is(manifestErr, ErrNoSuchUpload) {
					continue
				}
				return res, fmt.Errorf("read multipart manifest for %q/%q: %w", bucket, up.UploadID, manifestErr)
			}
			if !matchesLifecycleRule(rule, up.Key, manifest.ObjectTags, -1) {
				continue
			}
			identifier := bucket + "/" + up.Key + "#" + up.UploadID
			if _, seen := processed[identifier]; seen {
				continue
			}
			if ageDays(now, up.Initiated) < days {
				continue
			}
			res.MatchedCandidates++
			key := up.Key
			uploadID := up.UploadID
			applied, applyErr := budget.apply(func() error {
				return b.AbortMultipartUpload(ctx, bucket, key, uploadID)
			})
			if !applied {
				res.SkippedByLimit++
				continue
			}
			if applyErr != nil {
				return res, fmt.Errorf("abort multipart upload %q/%q/%q: %w", bucket, key, uploadID, applyErr)
			}
			res.AppliedActions++
			processed[identifier] = struct{}{}
		}
		if !list.IsTruncated {
			break
		}
		opts.KeyMarker = list.NextKeyMarker
		opts.UploadIDMarker = list.NextUploadIDMarker
		opts.HasUploadIDMarker = true
	}

	return res, nil
}

type keyVersionRecord struct {
	id   string
	meta metadataOnDisk
}

func (b *FSBackend) listKeyVersions(bucket, key string) ([]keyVersionRecord, error) {
	entries, err := os.ReadDir(b.objectVersionDir(bucket, key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list key versions for %q/%q: %w", bucket, key, err)
	}
	versions := make([]keyVersionRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		versionID, decErr := DecodeKey(strings.TrimSuffix(entry.Name(), ".json"))
		if decErr != nil {
			continue
		}
		meta, metaErr := b.readObjectVersionMeta(bucket, key, versionID)
		if metaErr != nil {
			continue
		}
		versions = append(versions, keyVersionRecord{id: versionID, meta: meta})
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].meta.LastModified.Equal(versions[j].meta.LastModified) {
			return versions[i].id > versions[j].id
		}
		return versions[i].meta.LastModified.After(versions[j].meta.LastModified)
	})
	return versions, nil
}

func matchesLifecyclePrefix(prefix, value string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return true
	}
	return strings.HasPrefix(value, prefix)
}

func matchesLifecycleRule(rule LifecycleRule, key string, tags map[string]string, size int64) bool {
	if !matchesLifecyclePrefix(rule.Prefix, key) {
		return false
	}
	if size >= 0 {
		if rule.ObjectSizeGreaterThan > 0 && size <= rule.ObjectSizeGreaterThan {
			return false
		}
		if rule.ObjectSizeLessThan > 0 && size >= rule.ObjectSizeLessThan {
			return false
		}
	}
	if len(rule.Tags) == 0 {
		return true
	}
	for k, expected := range rule.Tags {
		actual, ok := tags[k]
		if !ok || actual != expected {
			return false
		}
	}
	return true
}

func ruleMatchesCurrentExpiration(now, lastModified time.Time, rule LifecycleRule, days int) bool {
	if days > 0 && ageDays(now, lastModified) >= days {
		return true
	}
	if !rule.ExpirationDate.IsZero() && (now.Equal(rule.ExpirationDate) || now.After(rule.ExpirationDate)) {
		return true
	}
	return false
}

func ageDays(now, then time.Time) int {
	if then.IsZero() {
		return 0
	}
	if now.Before(then) {
		return 0
	}
	return int(now.Sub(then.UTC()) / (24 * time.Hour))
}

func (b *lifecycleActionBudget) apply(run func() error) (bool, error) {
	if b.maxActions > 0 && b.used >= b.maxActions {
		b.skipped++
		return false, nil
	}
	b.used++
	if b.dryRun {
		b.dryRunHits++
		return true, nil
	}
	if err := run(); err != nil {
		return true, err
	}
	b.executed++
	return true, nil
}
