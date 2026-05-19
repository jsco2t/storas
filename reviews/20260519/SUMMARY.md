# Review Summary — 2026-05-19

**Scope**: `all` (every tracked file in repository, ~145 files)
**Output dir**: `./reviews/20260519/`

---

## Total: 7 findings (1 Critical, 4 Important, 2 deduplicated)

---

## CRITICAL

### 1. Misleading error message masks underlying cause in TLS config loading

| Field | Value |
|-------|-------|
| **Confidence** | 85 |
| **File** | `internal/runtime/server.go:51-53` |
| **Source** | Reviewer 2 (Bug Detection) |

**Problem:** When `tls.LoadX509KeyPair()` fails, the original error is replaced with `"manual tls load failed: invalid tls certificate or key material"`. The real cause — file not found, permission denied, PEM decode failure, etc. — is lost entirely.

```go
// Before
return nil, fmt.Errorf("manual tls load failed: invalid tls certificate or key material")
```

**Fix:**
```go
// After
return nil, fmt.Errorf("manual tls load: %w", err)
```

---

## IMPORTANT

### 2. `MapError(nil)` silently produces an HTTP 500 response

| Field | Value |
|-------|-------|
| **Confidence** | 80 |
| **File** | `internal/s3err/errors.go:79-81` |
| **Source** | Reviewer 2 (Bug Detection) |

**Problem:** `MapError` treats nil input as a valid error and returns `InternalError` (HTTP 500). Under normal code paths callers check `err != nil` before calling MapError, but any unconditional invocation will fabricate a server error from nothing.

**Fix:** Document the nil-precondition or return zero-value APIError instead of fabricating InternalError:
```go
case err == nil:
    return APIError{}  // empty error, not fabricated InternalError
```

---

### 3. Context cancellations map to HTTP 400 (Bad Request) instead of meaningful status

| Field | Value |
|-------|-------|
| **Confidence** | 80 |
| **File** | `internal/s3err/errors.go:124-125` |
| **Source** | Reviewer 2 (Bug Detection) |

**Problem:** `context.Canceled` and `context.DeadlineExceeded` map to `RequestTimeout` (HTTP 400). Clients see a client-side error when the real cause is server-side timeout or request cancellation.

**Fix:**
```go
case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
    return APIError{Code: "InternalError", StatusCode: http.StatusServiceUnavailable} // 503
```

---

### 4. `handleGetBucketPolicy` ignores HTTP write error

| Field | Value |
|-------|-------|
| **Confidence** | 85 |
| **File** | `internal/api/service.go:602` |
| **Source** | Reviewer 3 (Code Quality), Reviewer 5 (Silent Failure Hunter) — deduplicated |

**Problem:** The bucket policy response payload is written with `_, _ = w.Write(pol)` — the write error is silently discarded. If client disconnects or network fails mid-write, the handler reports success and never logs the failure.

**Fix:**
```go
if _, err := w.Write(pol); err != nil {
    s.Logger.Error("failed to write bucket policy response", "error", err)
}
```

---

### 5. `handleCreateBucket` silently ignores read errors during XML decode

| Field | Value |
|-------|-------|
| **Confidence** | 80 |
| **File** | `internal/api/service.go:452-459` |
| **Source** | Reviewer 5 (Silent Failure Hunter) |

**Problem:** If the client sends a body that causes an I/O error during XML decoding, the error is treated as `io.EOF` (benign), and the bucket is created without the expected configuration. The failure goes undetected.

**Fix:** Add explicit check for non-EOF read errors after decode attempt.

---

### 6. `ensureLegacyNullVersion` silently discards JSON unmarshal error

| Field | Value |
|-------|-------|
| **Confidence** | 80 |
| **File** | `internal/storage/fs.go:1205-1207` |
| **Source** | Reviewer 5 (Silent Failure Hunter) |

**Problem:** When current object metadata is corrupt (truncated file, encode error, disk I/O), the error is silently swallowed and `nil` is returned. This marks corrupted metadata as "migration not needed," meaning subsequent reads will fail and the corruption is never flagged for repair.

**Fix:**
```go
if err := json.Unmarshal(metaBytes, &meta); err != nil {
    b.logger.Error("corrupt metadata during legacy migration", "key", key, "error", err)
    return fmt.Errorf("decode current metadata for migration: %w", err)
}
```

---

## No-findings Reviewers

| Reviewer | Result |
|----------|--------|
| 1 — Project Guidelines Compliance | PASS (no violations found) |
| 4 — Idiomatic Code Usage | PASS (idiomatic Go across all files) |
| 6 — Constant & DRY Consistency | PASS (no duplicated literals found at ≥ 80 confidence) |
| 7 — Documentation Accuracy | PASS (docs consistent with codebase) |
| 8 — Test Quality | PASS (strong coverage, clean test patterns) |

---

## Verification Log Files

| File | Lines | Status |
|------|-------|--------|
| `01-project-guidelines.md` | 44 | ✅ Verified |
| `02-bug-detection.md` | 103 | ✅ Verified |
| `03-code-quality.md` | 62 | ✅ Verified |
| `04-idiomatic-code.md` | 27 | ✅ Verified |
| `05-silent-failure-hunter.md` | 147 | ✅ Verified |
| `06-constant-dry-consistency.md` | 43 | ✅ Verified |
| `07-documentation-accuracy.md` | 29 | ✅ Verified |
| `08-test-quality.md` | 34 | ✅ Verified |

All log files exist, are non-empty, valid markdown, and contain the expected sections.
