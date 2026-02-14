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

type MultipartSweepOptions struct {
	StaleAfter            time.Duration
	MaxRemovals           int
	RemoveCorruptUploads  bool
	CleanupTemporaryFiles bool
	TempFileStaleAfter    time.Duration
}

type MultipartMaintenanceResult struct {
	BucketsScanned        int
	UploadsScanned        int
	StaleCandidatesFound  int
	UploadsRemoved        int
	CorruptedUploadsFound int
	CorruptedUploadsKept  int
	TempFilesRemoved      int
	SkippedByRemovalLimit int
}

type multipartSweepCandidate struct {
	bucket       string
	uploadID     string
	uploadDir    string
	lastActivity time.Time
	corrupt      bool
}

func (b *FSBackend) SweepStaleMultipartUploads(ctx context.Context, now time.Time, opts MultipartSweepOptions) (MultipartMaintenanceResult, error) {
	if opts.StaleAfter <= 0 {
		return MultipartMaintenanceResult{}, ErrInvalidRequest
	}
	if opts.TempFileStaleAfter <= 0 {
		opts.TempFileStaleAfter = opts.StaleAfter
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	buckets, err := b.ListBuckets(ctx)
	if err != nil {
		return MultipartMaintenanceResult{}, err
	}

	result := MultipartMaintenanceResult{}
	candidates := make([]multipartSweepCandidate, 0)
	var errs []error

	for _, bucket := range buckets {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.BucketsScanned++

		entries, readErr := os.ReadDir(b.multipartRoot(bucket))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			errs = append(errs, fmt.Errorf("list multipart root for bucket %q: %w", bucket, readErr))
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})

		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if !entry.IsDir() {
				continue
			}
			result.UploadsScanned++

			uploadID := strings.TrimSpace(entry.Name())
			uploadDir := b.multipartUploadDir(bucket, uploadID)

			if opts.CleanupTemporaryFiles {
				removed, cleanupErr := cleanupMultipartTempFiles(uploadDir, now, opts.TempFileStaleAfter)
				result.TempFilesRemoved += removed
				if cleanupErr != nil {
					errs = append(errs, fmt.Errorf("cleanup temp files for multipart upload %q/%q: %w", bucket, uploadID, cleanupErr))
				}
			}

			stale, corrupt, lastActivity, evalErr := assessMultipartUpload(uploadDir, func() (multipartManifest, error) {
				return b.readMultipartManifest(ctx, bucket, uploadID)
			}, now, opts.StaleAfter)
			if evalErr != nil {
				errs = append(errs, fmt.Errorf("evaluate multipart upload %q/%q: %w", bucket, uploadID, evalErr))
				continue
			}
			if !stale {
				continue
			}
			result.StaleCandidatesFound++
			if corrupt {
				result.CorruptedUploadsFound++
			}
			candidates = append(candidates, multipartSweepCandidate{
				bucket:       bucket,
				uploadID:     uploadID,
				uploadDir:    uploadDir,
				lastActivity: lastActivity,
				corrupt:      corrupt,
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].lastActivity.Equal(candidates[j].lastActivity) {
			if candidates[i].bucket == candidates[j].bucket {
				return candidates[i].uploadID < candidates[j].uploadID
			}
			return candidates[i].bucket < candidates[j].bucket
		}
		return candidates[i].lastActivity.Before(candidates[j].lastActivity)
	})

	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if candidate.corrupt && !opts.RemoveCorruptUploads {
			result.CorruptedUploadsKept++
			continue
		}
		if opts.MaxRemovals > 0 && result.UploadsRemoved >= opts.MaxRemovals {
			result.SkippedByRemovalLimit++
			continue
		}
		if removeErr := os.RemoveAll(candidate.uploadDir); removeErr != nil {
			errs = append(errs, fmt.Errorf("remove multipart upload %q/%q: %w", candidate.bucket, candidate.uploadID, removeErr))
			continue
		}
		result.UploadsRemoved++
	}

	return result, errors.Join(errs...)
}

func assessMultipartUpload(uploadDir string, loadManifest func() (multipartManifest, error), now time.Time, staleAfter time.Duration) (bool, bool, time.Time, error) {
	manifest, err := loadManifest()
	if err == nil {
		latestFSActivity, actErr := latestUploadActivity(uploadDir)
		if actErr != nil {
			return false, false, time.Time{}, actErr
		}
		if manifest.CreatedAt.IsZero() {
			return now.Sub(latestFSActivity) >= staleAfter, true, latestFSActivity, nil
		}
		lastActivity := manifest.CreatedAt.UTC()
		if latestFSActivity.After(lastActivity) {
			lastActivity = latestFSActivity
		}
		return now.Sub(lastActivity) >= staleAfter, false, lastActivity, nil
	}

	lastActivity, activityErr := latestUploadActivity(uploadDir)
	if activityErr != nil {
		if os.IsNotExist(activityErr) {
			return false, false, time.Time{}, nil
		}
		return false, false, time.Time{}, activityErr
	}
	return now.Sub(lastActivity) >= staleAfter, true, lastActivity, nil
}

func latestUploadActivity(uploadDir string) (time.Time, error) {
	root := filepath.Clean(uploadDir)
	info, err := os.Stat(root)
	if err != nil {
		return time.Time{}, err
	}
	latest := info.ModTime().UTC()
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		i, err := d.Info()
		if err != nil {
			return err
		}
		mod := i.ModTime().UTC()
		if mod.After(latest) {
			latest = mod
		}
		return nil
	})
	if walkErr != nil {
		return time.Time{}, walkErr
	}
	return latest, nil
}

func cleanupMultipartTempFiles(uploadDir string, now time.Time, staleAfter time.Duration) (int, error) {
	entries, err := os.ReadDir(filepath.Clean(uploadDir))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var errs []error
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "part-") || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			errs = append(errs, infoErr)
			continue
		}
		if now.Sub(info.ModTime().UTC()) < staleAfter {
			continue
		}
		if err := os.Remove(filepath.Join(uploadDir, entry.Name())); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

func defaultMultipartSweepOptions(staleAfter time.Duration) MultipartSweepOptions {
	return MultipartSweepOptions{
		StaleAfter:            staleAfter,
		MaxRemovals:           0,
		RemoveCorruptUploads:  true,
		CleanupTemporaryFiles: true,
		TempFileStaleAfter:    staleAfter,
	}
}
