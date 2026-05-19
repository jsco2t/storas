# Reviewer 2: Bug Detection

**Scope**: All tracked `.go` files across `/cmd/`, `/internal/`, `/test/`
**Date**: 2026-05-19

---

## Finding 1 — Misleading error message masks underlying cause

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **Confidence** | 85 |
| **File** | `internal/runtime/server.go` |
| **Line(s)** | 51–53 |

### Description
When `tls.LoadX509KeyPair()` fails, the error is wrapped in a generic message: `"manual tls load failed: invalid tls certificate or key material"`. The original error from `LoadX509KeyPair` — which could be "no such file or directory", "permission denied", "malformed PEM data", or any number of real problems — is lost. This error message assumes the root cause is always invalid certificate/key content but the failure surface is broad.

```go
pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
if err != nil {
    return nil, fmt.Errorf("manual tls load failed: invalid tls certificate or key material") // original error lost
}
```

### Guideline Reference
Bug Detection — "flag **misleading error messages** that assume a single root cause when the failure could have several"

### Fix Suggestion
Preserve the underlying error so operators can diagnose real issues (missing files, permissions, corrupt PEM data):

```go
pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
if err != nil {
    return nil, fmt.Errorf("manual tls load: %w", err)
}
```

---

## Finding 2 — `MapError(nil)` silently produces a 500 Internal Error

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 80 |
| **File** | `internal/s3err/errors.go` |
| **Line(s)** | 79–81 |

### Description
`MapError` treats `err == nil` as a valid input and returns `InternalError` (HTTP 500). While the normal call sites in `service.go` guard against passing nil (e.g., `if err != nil { s3err.MapError(err) }`), this is a latent risk: any code path that unconditionally calls `MapError(nil)` — for example, a future refactor or a helper function that always invokes it — will fabricate an HTTP 500 response from a nil error.

```go
case err == nil:
    return InternalError
```

### Guideline Reference
Bug Detection — "logic errors; ... security vulnerabilities"

### Fix Suggestion
Either document the nil-precondition in the function contract and add a defensive panic, or change behavior to propagate nil through cleanly:

```go
case err == nil:
    // Return zero-value APIError (empty code/message) rather than fabricating InternalError.
    return APIError{}
```
Or add an explicit precondition document / comment at the function level. The safest fix that still surfaces the problem is to change the default arm `default: return InternalError` so it only fires for **unmapped** errors, not nil input — since nil has a defined meaning in Go (no error).

---

## Finding 3 — Context cancellations map to HTTP 400 instead of meaningful status

| Field | Value |
|-------|-------|
| **Severity** | Important |
| **Confidence** | 80 |
| **File(s)** | `internal/s3err/errors.go:124-125` |
| **Line(s)** | 124–125 |

### Description
`context.Canceled` and `context.DeadlineExceeded` errors are mapped to `RequestTimeout` (HTTP 400 Bad Request). Clients interpreting these responses see a client-side error when the real cause is server-side timeout or request cancellation (which could be HTTP 503 or even 504 depending on semantics).

```go
case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
    return RequestTimeout // HTTP 400
```

### Guideline Reference
Bug Detection — "performance problems" / "logic errors"

### Fix Suggestion
Use a more semantically appropriate status code. The closest S3-compatible choice is to map these to the `NoResponseBody` error path or add a new mapping:
```go
case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
    return APIError{Code: "InternalError", StatusCode: http.StatusServiceUnavailable} // 503
```

---

**Summary of Findings**: 3 findings (1 Critical, 2 Important)
