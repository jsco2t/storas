# Reviewer 5: Silent Failure Hunter

**Scope**: All tracked `.go` files across `/cmd/`, `/internal/`, `/test/`
**Date**: 2026-05-19

---

## Finding — `handleGetBucketPolicy` ignores HTTP write error (same as Code Quality)

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 85 |
| **File** | `internal/api/service.go` |
| **Line(s)** | 602 |

### Description
```go
_, _ = w.Write(pol)
```
The HTTP write response for bucket policy content discards the `(int, error)` return value. If the client disconnects mid-write or a network error occurs, the handler returns nil (success). Unlike the router.go health endpoints where this pattern is benign, bucket policies are user-facing payloads that can be substantial in size — silently dropping failures here means the caller never knows if the response was actually delivered.

### Guideline Reference
Silent Failure Hunter — "ignored errors that should be logged"

### Fix Suggestion
```go
if _, err := w.Write(pol); err != nil {
    s.Logger.Error("failed to write bucket policy response", "error", err)
}
```

---

## Finding — `handleCreateBucket` silently ignores XML decode error for read errors

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 80 |
| **File** | `internal/api/service.go` |
| **Line(s)** | 452-459 |

### Description
```go
decoder := xml.NewDecoder(r.Body)
var cfg createBucketConfiguration
if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
    if isRequestBodyTooLarge(err) {
        return storage.ErrEntityTooLarge
    }
    return storage.ErrInvalidRequest
}
```

This handler only checks for decode errors but not read errors. If the client sends a malformed body that causes an I/O error (not EOF), the error is treated as `io.EOF` (nil error in this branch) and the bucket creation proceeds normally without the expected XML payload. The bucket will be created with default/empty configuration.

### Guideline Reference
Silent Failure Hunter — "unchecked errors"; "optimistic defaults (functions returning a fallback on failure)"

### Fix Suggestion
Check for non-read-error conditions explicitly:
```go
if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
    if isRequestBodyTooLarge(err) {
        return storage.ErrEntityTooLarge
    }
    return storage.ErrInvalidRequest
}
// Also handle the case where r.Body could not be read at all:
if _, err := io.Copy(io.Discard, r.Body); err != nil && err != io.EOF {
    return storage.ErrInvalidRequest // or map to a proper S3 error
}
```

---

## Finding — HTTP `w.WriteHeader()` followed by write failure silently swallowed (service.go)

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 80 |
| **File** | `internal/api/service.go` |
| **Line(s)** | 600-604, and similar patterns at lines 549-551, 523-528 |

### Description
Several handler methods in the S3 dispatch chain call `w.WriteHeader(...)` followed by a write that discards errors. The specific instance is `handleGetBucketPolicy`, but the pattern also appears in other handlers like:
- `handleGetBucketVersioning` (line 549): same pattern with XML encoding error suppressed
- `handlePutBucketACL` (line 527-528): no write, just status — benign
- Various multipart and object handlers use `xml.NewEncoder().Encode()` where the error is checked but intermediate writes may not be

The primary flag-worthy case remains `handleGetBucketPolicy:602`.

### Guideline Reference
Silent Failure Hunter — "ignored errors that should be logged"

---

## Finding — `ensureLegacyNullVersion` silently discards JSON unmarshal error

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 80 |
| **File** | `internal/storage/fs.go` |
| **Line(s)** | 1205-1207 |

### Description
```go
if err := json.Unmarshal(metaBytes, &meta); err != nil {
    return nil  // silently returns success even though metadata was corrupt
}
```

When the current object metadata JSON is corrupt (truncated file, encoding error, disk I/O), this function returns `nil` — indicating "no migration needed." This means:
1. The corruption is never detected or repaired
2. Subsequent reads of that key will fail with decode errors
3. The corrupted object is neither cleaned nor flagged

This is an optimistic default: "metadata parse failed → assume all is fine" rather than propagating the error for investigation.

### Guideline Reference
Silent Failure Hunter — "optimistic defaults (functions returning a fallback on failure instead of propagating an error)"

### Fix Suggestion
Log and propagate the error so that operators can investigate corrupted metadata:
```go
if err := json.Unmarshal(metaBytes, &meta); err != nil {
    b.logger.Error("corrupt metadata during legacy migration", "key", key, "error", err)
    return fmt.Errorf("decode current metadata for migration: %w", err)
}
```

---

## Summary Table

| # | Location | Issue Type | Confidence | Severity |
|---|----------|-----------|------------|----------|
| 1 | service.go:602 | Ignored HTTP write error | 85 | Important |
| 2 | service.go:452-459 | Unchecked read error in XML decode | 80 | Important |
| 3 | fs.go:1205-1207 | Optimistic default on corrupt metadata | 80 | Important |

---

**Summary of Findings**: 3 findings (0 Critical, 3 Important)
