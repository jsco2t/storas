package storage

import (
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMultipartPartNumber = 10000
)

var multipartUploadIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

type multipartManifest struct {
	UploadID     string            `json:"upload_id"`
	Key          string            `json:"key"`
	ContentType  string            `json:"content_type"`
	UserMetadata map[string]string `json:"user_metadata"`
	ObjectTags   map[string]string `json:"object_tags,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type multipartPartMeta struct {
	PartNumber   int       `json:"part_number"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
}

func (b *FSBackend) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata ObjectMetadata) (string, error) {
	if err := ensureContext(ctx); err != nil {
		return "", err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return "", err
	}
	if strings.TrimSpace(key) == "" {
		return "", ErrNoSuchKey
	}

	uploadID, err := generateMultipartUploadID()
	if err != nil {
		return "", err
	}
	uploadDir := b.multipartUploadDir(bucket, uploadID)
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		return "", fmt.Errorf("create multipart upload dir: %w", err)
	}

	manifest := multipartManifest{
		UploadID:     uploadID,
		Key:          key,
		ContentType:  metadata.ContentType,
		UserMetadata: cloneMap(metadata.UserMetadata),
		ObjectTags:   cloneMap(metadata.ObjectTags),
		CreatedAt:    time.Now().UTC(),
	}
	if err := b.writeMultipartManifest(bucket, uploadID, manifest); err != nil {
		return "", err
	}

	return uploadID, nil
}

func (b *FSBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, body io.Reader) (MultipartPartInfo, error) {
	if err := ensureContext(ctx); err != nil {
		return MultipartPartInfo{}, err
	}
	if err := validateUploadID(uploadID); err != nil {
		return MultipartPartInfo{}, err
	}
	if partNumber <= 0 {
		return MultipartPartInfo{}, ErrInvalidPart
	}
	if partNumber > maxMultipartPartNumber {
		return MultipartPartInfo{}, ErrInvalidPart
	}
	manifest, err := b.readMultipartManifest(ctx, bucket, uploadID)
	if err != nil {
		return MultipartPartInfo{}, err
	}
	if manifest.Key != key {
		return MultipartPartInfo{}, ErrNoSuchUpload
	}

	tmpPart, err := os.CreateTemp(b.multipartUploadDir(bucket, uploadID), "part-*.tmp")
	if err != nil {
		return MultipartPartInfo{}, fmt.Errorf("create multipart temp part: %w", err)
	}
	defer func() { _ = os.Remove(tmpPart.Name()) }()

	h := md5.New() //nolint:gosec // S3 multipart ETag behavior is MD5-based per part.
	written, err := io.Copy(io.MultiWriter(tmpPart, h), body)
	if err != nil {
		_ = tmpPart.Close()
		return MultipartPartInfo{}, fmt.Errorf("write multipart part: %w", err)
	}
	if written > b.maxObjectSize {
		_ = tmpPart.Close()
		return MultipartPartInfo{}, ErrEntityTooLarge
	}
	if err := tmpPart.Sync(); err != nil {
		_ = tmpPart.Close()
		return MultipartPartInfo{}, fmt.Errorf("sync multipart part: %w", err)
	}
	if err := tmpPart.Close(); err != nil {
		return MultipartPartInfo{}, fmt.Errorf("close multipart part: %w", err)
	}

	now := time.Now().UTC()
	etag := hex.EncodeToString(h.Sum(nil))
	meta := multipartPartMeta{PartNumber: partNumber, Size: written, ETag: etag, LastModified: now}
	if err := b.writeMultipartPartMeta(bucket, uploadID, meta); err != nil {
		return MultipartPartInfo{}, err
	}

	finalPath := b.multipartPartPath(bucket, uploadID, partNumber)
	if err := os.Rename(tmpPart.Name(), finalPath); err != nil {
		return MultipartPartInfo{}, fmt.Errorf("commit multipart part: %w", err)
	}

	return MultipartPartInfo{PartNumber: partNumber, Size: written, ETag: etag, LastModified: now}, nil
}

func (b *FSBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) (ObjectInfo, error) {
	if err := ensureContext(ctx); err != nil {
		return ObjectInfo{}, err
	}
	if err := validateUploadID(uploadID); err != nil {
		return ObjectInfo{}, err
	}
	manifest, err := b.readMultipartManifest(ctx, bucket, uploadID)
	if err != nil {
		return ObjectInfo{}, err
	}
	if manifest.Key != key {
		return ObjectInfo{}, ErrNoSuchUpload
	}

	partMetas, err := b.listMultipartPartMetas(ctx, bucket, uploadID)
	if err != nil {
		return ObjectInfo{}, err
	}
	if len(partMetas) == 0 {
		return ObjectInfo{}, ErrInvalidPart
	}

	selected, err := selectCompletedParts(partMetas, parts)
	if err != nil {
		return ObjectInfo{}, err
	}

	readers := make([]io.Reader, 0, len(selected))
	closers := make([]io.Closer, 0, len(selected))
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()

	for _, part := range selected {
		if err := ctx.Err(); err != nil {
			return ObjectInfo{}, err
		}
		partPath := b.multipartPartPath(bucket, uploadID, part.PartNumber)
		st, statErr := os.Stat(partPath)
		if statErr != nil || st.IsDir() || st.Size() != part.Size {
			return ObjectInfo{}, ErrInvalidPart
		}
		f, openErr := os.Open(partPath)
		if openErr != nil {
			return ObjectInfo{}, fmt.Errorf("open multipart part: %w", openErr)
		}
		readers = append(readers, f)
		closers = append(closers, f)
	}

	obj, err := b.PutObject(ctx, bucket, key, io.MultiReader(readers...), ObjectMetadata{
		ContentType:  manifest.ContentType,
		UserMetadata: cloneMap(manifest.UserMetadata),
		ObjectTags:   cloneMap(manifest.ObjectTags),
	})
	if err != nil {
		return ObjectInfo{}, err
	}

	if err := os.RemoveAll(b.multipartUploadDir(bucket, uploadID)); err != nil {
		return ObjectInfo{}, fmt.Errorf("cleanup multipart upload: %w", err)
	}
	return obj, nil
}

func (b *FSBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	if err := validateUploadID(uploadID); err != nil {
		return err
	}
	manifest, err := b.readMultipartManifest(ctx, bucket, uploadID)
	if err != nil {
		if errors.Is(err, ErrNoSuchUpload) {
			return nil
		}
		return err
	}
	if manifest.Key != key {
		return nil
	}
	if err := os.RemoveAll(b.multipartUploadDir(bucket, uploadID)); err != nil {
		return fmt.Errorf("abort multipart upload: %w", err)
	}
	return nil
}

func (b *FSBackend) ListMultipartUploads(ctx context.Context, bucket string, opts MultipartUploadListOptions) (MultipartUploadListResult, error) {
	if err := ensureContext(ctx); err != nil {
		return MultipartUploadListResult{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return MultipartUploadListResult{}, err
	}
	entries, err := os.ReadDir(b.multipartRoot(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return MultipartUploadListResult{}, nil
		}
		return MultipartUploadListResult{}, fmt.Errorf("read multipart root: %w", err)
	}

	uploads := make([]MultipartUpload, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return MultipartUploadListResult{}, err
		}
		if !entry.IsDir() {
			continue
		}
		manifest, readErr := b.readMultipartManifest(ctx, bucket, entry.Name())
		if readErr != nil {
			continue
		}
		if opts.Prefix != "" && !strings.HasPrefix(manifest.Key, opts.Prefix) {
			continue
		}
		uploads = append(uploads, MultipartUpload{Key: manifest.Key, UploadID: manifest.UploadID, Initiated: manifest.CreatedAt})
	}

	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key == uploads[j].Key {
			return uploads[i].UploadID < uploads[j].UploadID
		}
		return uploads[i].Key < uploads[j].Key
	})

	start := 0
	if opts.KeyMarker != "" {
		for i, up := range uploads {
			if up.Key > opts.KeyMarker {
				start = i
				break
			}
			if up.Key == opts.KeyMarker {
				if opts.HasUploadIDMarker {
					if up.UploadID > opts.UploadIDMarker {
						start = i
						break
					}
				}
				start = len(uploads)
				continue
			}
			start = len(uploads)
		}
	}

	maxUploads := opts.MaxUploads
	if maxUploads <= 0 {
		maxUploads = 1000
	}

	end := start + maxUploads
	if end > len(uploads) {
		end = len(uploads)
	}
	result := MultipartUploadListResult{Uploads: uploads[start:end], IsTruncated: end < len(uploads)}
	if result.IsTruncated {
		last := result.Uploads[len(result.Uploads)-1]
		result.NextKeyMarker = last.Key
		result.NextUploadIDMarker = last.UploadID
	}
	return result, nil
}

func (b *FSBackend) ListParts(ctx context.Context, bucket, key, uploadID string, opts ListPartsOptions) (ListPartsResult, error) {
	if err := ensureContext(ctx); err != nil {
		return ListPartsResult{}, err
	}
	if err := validateUploadID(uploadID); err != nil {
		return ListPartsResult{}, err
	}
	manifest, err := b.readMultipartManifest(ctx, bucket, uploadID)
	if err != nil {
		return ListPartsResult{}, err
	}
	if manifest.Key != key {
		return ListPartsResult{}, ErrNoSuchUpload
	}

	metas, err := b.listMultipartPartMetas(ctx, bucket, uploadID)
	if err != nil {
		return ListPartsResult{}, err
	}
	maxParts := opts.MaxParts
	if maxParts <= 0 {
		maxParts = 1000
	} else if maxParts > 1000 {
		maxParts = 1000
	}

	filtered := make([]multipartPartMeta, 0, len(metas))
	for _, m := range metas {
		if err := ctx.Err(); err != nil {
			return ListPartsResult{}, err
		}
		if m.PartNumber > opts.PartNumberMarker {
			filtered = append(filtered, m)
		}
	}

	result := ListPartsResult{}
	for i, m := range filtered {
		if err := ctx.Err(); err != nil {
			return ListPartsResult{}, err
		}
		if i >= maxParts {
			result.IsTruncated = true
			result.NextPartNumberMarker = filtered[i-1].PartNumber
			break
		}
		result.Parts = append(result.Parts, MultipartPartInfo{PartNumber: m.PartNumber, Size: m.Size, ETag: m.ETag, LastModified: m.LastModified})
	}
	if result.IsTruncated && result.NextPartNumberMarker == 0 && len(result.Parts) > 0 {
		result.NextPartNumberMarker = result.Parts[len(result.Parts)-1].PartNumber
	}
	return result, nil
}

func (b *FSBackend) multipartRoot(bucket string) string {
	return filepath.Join(b.bucketDir(bucket), "multipart")
}

func (b *FSBackend) multipartUploadDir(bucket, uploadID string) string {
	return filepath.Join(b.multipartRoot(bucket), uploadID)
}

func (b *FSBackend) multipartManifestPath(bucket, uploadID string) string {
	return filepath.Join(b.multipartUploadDir(bucket, uploadID), "manifest.json")
}

func (b *FSBackend) multipartPartPath(bucket, uploadID string, partNumber int) string {
	return filepath.Join(b.multipartUploadDir(bucket, uploadID), fmt.Sprintf("part-%05d.bin", partNumber))
}

func (b *FSBackend) multipartPartMetaPath(bucket, uploadID string, partNumber int) string {
	return filepath.Join(b.multipartUploadDir(bucket, uploadID), fmt.Sprintf("part-%05d.json", partNumber))
}

func (b *FSBackend) readMultipartManifest(ctx context.Context, bucket, uploadID string) (multipartManifest, error) {
	if err := ensureContext(ctx); err != nil {
		return multipartManifest{}, err
	}
	if err := validateUploadID(uploadID); err != nil {
		return multipartManifest{}, err
	}
	if err := b.HeadBucket(ctx, bucket); err != nil {
		return multipartManifest{}, err
	}
	bytes, err := os.ReadFile(b.multipartManifestPath(bucket, uploadID))
	if err != nil {
		if os.IsNotExist(err) {
			return multipartManifest{}, ErrNoSuchUpload
		}
		return multipartManifest{}, fmt.Errorf("read multipart manifest: %w", err)
	}
	var manifest multipartManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return multipartManifest{}, fmt.Errorf("decode multipart manifest: %w", err)
	}
	return manifest, nil
}

func (b *FSBackend) writeMultipartManifest(bucket, uploadID string, manifest multipartManifest) error {
	bytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal multipart manifest: %w", err)
	}
	if err := os.WriteFile(b.multipartManifestPath(bucket, uploadID), bytes, 0o600); err != nil {
		return fmt.Errorf("write multipart manifest: %w", err)
	}
	return nil
}

func (b *FSBackend) writeMultipartPartMeta(bucket, uploadID string, meta multipartPartMeta) error {
	bytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal multipart part meta: %w", err)
	}
	if err := os.WriteFile(b.multipartPartMetaPath(bucket, uploadID, meta.PartNumber), bytes, 0o600); err != nil {
		return fmt.Errorf("write multipart part meta: %w", err)
	}
	return nil
}

func (b *FSBackend) listMultipartPartMetas(ctx context.Context, bucket, uploadID string) ([]multipartPartMeta, error) {
	if err := ensureContext(ctx); err != nil {
		return nil, err
	}
	if err := validateUploadID(uploadID); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(b.multipartUploadDir(bucket, uploadID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSuchUpload
		}
		return nil, fmt.Errorf("read multipart upload dir: %w", err)
	}
	parts := make([]multipartPartMeta, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "part-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		partNumberStr := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "part-"), ".json")
		partNumber, convErr := strconv.Atoi(partNumberStr)
		if convErr != nil {
			continue
		}
		if partNumber <= 0 || partNumber > maxMultipartPartNumber {
			continue
		}
		metaBytes, readErr := os.ReadFile(b.multipartPartMetaPath(bucket, uploadID, partNumber))
		if readErr != nil {
			return nil, fmt.Errorf("read multipart part meta: %w", readErr)
		}
		var meta multipartPartMeta
		if unmarshalErr := json.Unmarshal(metaBytes, &meta); unmarshalErr != nil {
			return nil, fmt.Errorf("decode multipart part meta: %w", unmarshalErr)
		}
		parts = append(parts, meta)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
	return parts, nil
}

func selectCompletedParts(available []multipartPartMeta, requested []CompletedPart) ([]multipartPartMeta, error) {
	byPart := make(map[int]multipartPartMeta, len(available))
	for _, part := range available {
		byPart[part.PartNumber] = part
	}

	if len(requested) == 0 {
		out := make([]multipartPartMeta, 0, len(available))
		out = append(out, available...)
		return out, nil
	}

	out := make([]multipartPartMeta, 0, len(requested))
	lastPartNumber := 0
	seen := make(map[int]struct{}, len(requested))
	for _, req := range requested {
		if req.PartNumber <= 0 || req.PartNumber > maxMultipartPartNumber {
			return nil, ErrInvalidPart
		}
		if _, ok := seen[req.PartNumber]; ok {
			return nil, ErrInvalidPart
		}
		seen[req.PartNumber] = struct{}{}
		if lastPartNumber > 0 && req.PartNumber <= lastPartNumber {
			return nil, ErrInvalidPartOrder
		}
		lastPartNumber = req.PartNumber

		part, ok := byPart[req.PartNumber]
		if !ok {
			return nil, ErrInvalidPart
		}
		if strings.Trim(strings.TrimSpace(req.ETag), "\"") != "" && strings.Trim(strings.TrimSpace(req.ETag), "\"") != part.ETag {
			return nil, ErrInvalidPart
		}
		out = append(out, part)
	}
	return out, nil
}

func validateUploadID(uploadID string) error {
	if strings.TrimSpace(uploadID) == "" {
		return ErrInvalidRequest
	}
	if strings.Contains(uploadID, "/") || strings.Contains(uploadID, "\\") {
		return ErrInvalidRequest
	}
	if filepath.Clean(uploadID) != uploadID {
		return ErrInvalidRequest
	}
	if !multipartUploadIDPattern.MatchString(uploadID) {
		return ErrInvalidRequest
	}
	return nil
}

func generateMultipartUploadID() (string, error) {
	var entropy [16]byte
	if _, err := cryptorand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("read multipart upload entropy: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])
	return "up-" + encoded, nil
}
