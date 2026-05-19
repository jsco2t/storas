# Reviewer 3: Code Quality

**Scope**: All tracked `.go` files across `/cmd/`, `/internal/`, `/test/`
**Date**: 2026-05-19

---

## Finding — `handleGetBucketPolicy` ignores HTTP write error

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 80 |
| **File** | `internal/api/service.go` |
| **Line(s)** | 596-604 |

### Description
The `handleGetBucketPolicy` handler discards the return value of `w.Write()`. If the HTTP connection is broken (client disconnected, network error), the write failure goes unnoticed — both the function returns nil (success) and no log entry captures the transport error.

```go
_, _ = w.Write(pol)   // line 602 — errors completely ignored
return nil             // function reports success regardless
```

This pattern is consistent across two other HTTP response writes in `internal/s3/router.go:44,59` (health/live endpoints), but those are acceptable because the health endpoint body is trivially small and non-critical. The bucket policy write is a user-facing payload that could be any size — silently dropping a failed write here reduces reliability.

### Guideline Reference
Code Quality — "missing critical error handling"

### Fix Suggestion
Log the write error to assist with diagnostics:

```go
if _, err := w.Write(pol); err != nil {
    s.Logger.Error("failed to write bucket policy response", "error", err)
}
```

---

## No Duplication Issues Found

- Mutex locking patterns (`b.mutationMu.Lock()` / `defer b.mutationMu.Unlock()`) are used consistently across all filesystem write operations in `internal/storage/fs.go` ✅
- Atomic file writes encapsulated in a single shared `writeFileAtomic()` function ✅
- Error mapping centralized in `s3err.MapError()` ✅
- Lifecycle filter parsing consolidated in `validateLifecycleConfiguration()` ✅

**Status: PASS** (no duplication or structural quality issues detected)

---

## Test Coverage Assessment

Tests found for all core packages:
- `internal/api/service_test.go` — comprehensive auth, dispatch, and S3 endpoint coverage
- `internal/storage/fs_test.go` — object lifecycle, versioning, listing
- `internal/stress/` — concurrency stress tests present ✅
- `test/integration/` — integration test suite with real HTTP server ✅

---

**Summary of Findings**: 1 finding (0 Critical, 1 Important)
