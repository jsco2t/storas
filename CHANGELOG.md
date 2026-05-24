# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-05-23

### Added

- `Makefile`, `scripts/tag-release.py`
  - Added `make tag-patch`, `make tag-minor`, `make tag-major` targets and a
    semver release tagging helper script.
  - `tag-release.py` now refuses to create a tag unless `CHANGELOG.md`
    contains both a `## [X.Y.Z]` section heading and a matching
    `[X.Y.Z]: <url>` link reference for the new version.
- `internal/api`, `internal/runtime`, `internal/s3`, `internal/s3err`
  - New tests covering write-failure logging, nil-logger guards, TLS error
    preservation, and context-cancellation status mapping (including
    wrapped-error cases).

### Changed

- `internal/api`, `internal/s3`
  - Replaced silent `_, _ = w.Write(...)` patterns in the router and API
    handlers with checked writes that log failures via `slog`. A nil
    logger guard in `logWriteErr` prevents panics when the logger field
    is not injected.
  - `RouterConfig` and `APIConfig` now consistently accept an injected
    `*slog.Logger`.
- `internal/api`
  - `createBucket`, `putBucketVersioning`, and `completeMultipartUpload`
    now read the request body with `io.ReadAll` + `xml.Unmarshal` instead
    of a streaming `xml.NewDecoder`, avoiding goroutine leaks on decode
    errors and brittle mid-decode `io.EOF` handling.
- `internal/s3err`
  - `MapError(nil)` now returns a zero-value `APIError` instead of
    `InternalError`, so callers can distinguish "no error" from
    "unmapped".

### Fixed

- `internal/s3err`
  - `context.Canceled` now maps to `RequestTimeout` (HTTP 400) and
    `context.DeadlineExceeded` maps to `InternalError` (HTTP 503). The
    two were previously collapsed onto the same 503 response, which
    misled clients about whether to retry and inflated server-side
    "service-unavailable" metrics for ordinary client disconnects.
- `internal/runtime`
  - TLS startup errors are now wrapped with `%w` so callers can inspect
    the underlying error via `errors.Is` / `errors.As`.
- `internal/storage`
  - `ensureLegacyNullVersion` no longer silently swallows corrupt
    metadata during legacy-to-null-version migration; it now logs and
    returns a wrapped error so versioning cannot be enabled on a bucket
    with unrecoverable legacy state.

## [0.1.2] - 2026-04-06

### Changed

- `internal/storage`
  - `FSBackend` now accepts an injected `*slog.Logger` at construction time; the application logger is propagated
    into the backend instead of falling back to the global logger.
  - Removed unused `defaultMultipartSweepOptions` function.
- `internal/api`, `internal/sigv4`, `internal/s3`, `internal/policy`
  - Extracted repeated string literals into named constants: S3 XML namespace, local owner identity, SigV4 terminal
    suffix, health-check endpoint paths, and S3 ARN prefix.

### Fixed

- `internal/storage`
  - Atomic version commit now rolls back partial files (payload and metadata) on write failure, preventing orphaned
    data on disk.
  - `DeleteBucketLifecycle` and `readBucketMetadata` now propagate unexpected filesystem errors instead of silently
    discarding them.
  - Streaming upload body is now bounded by `io.LimitReader` before the size check, preventing unbounded disk
    writes on oversized requests.
  - Replaced deprecated `os.IsNotExist` calls with `errors.Is(err, os.ErrNotExist)` throughout the storage,
    multipart, and lifecycle packages.
- `internal/api`
  - Fixed a TOCTOU race in the bucket policy cache where a concurrently-loaded entry could be silently overwritten.
- `internal/s3err`
  - `ErrInvalidPartNumber` promoted to a sentinel error variable; error mapping now uses `errors.Is` instead of
    string comparison, enabling proper error wrapping.
- `internal/tls/acme`
  - Replaced `os.IsNotExist` calls with `errors.Is(err, os.ErrNotExist)` in stored-certificate loading.
- `cmd/storas`
  - Server shutdown path now uses `errors.Is(err, http.ErrServerClosed)` instead of direct value comparison.

## [0.1.1] - 2026-02-18

### Added

- `examples/docker-compose/`
  - Added ready-to-run Docker Compose stack examples for HTTP, self-signed TLS, and ACME DNS deployments, including per-stack mini READMEs and environment templates.
- `README.md`
  - Added GHCR-based container quick-start documentation and links to containerized deployment examples.

### Changed

- `.github/workflows/ci.yml`
  - Added GitHub Container Registry image publish workflow support using `ghcr.io/<owner>/storas:<tag>` naming.

## [0.1.0] - 2026-02-17

### Added

- `cmd/`
  - Initial `storas` service entrypoint and startup wiring (`cmd/storas`).
- `internal/s3`, `internal/api`, `internal/storage`
  - Initial S3-compatible bucket/object API surface including core CRUD, multipart upload lifecycle, copy support, ACL compatibility endpoints/headers, versioning APIs, lifecycle configuration APIs, and bucket policy APIs.
- `internal/sigv4`, `internal/authz`, `internal/policy`
  - SigV4 request authentication, authorization engine integration, and bucket policy evaluation (including explicit deny handling and supported condition operator/key subsets).
- `internal/tls`, `internal/runtime`, `internal/config`, `internal/logging`
  - Runtime configuration loading/validation, HTTP server runtime/security controls, structured logging modes, and TLS support for self-signed, manual certificates, and ACME DNS-01 (Cloudflare provider path).
- `configs/`
  - Example configuration profiles for HTTP, self-signed TLS, ACME DNS, and authorization policy files.
- `docs/`, `docs/adr/`, `docs/development/`
  - Initial operator and developer documentation covering configuration, authorization model, S3 support boundaries, compatibility strategy, TLS operations, resiliency guidance, and architecture decisions.
- `test/`, `internal/**/*_test.go`
  - Unit, integration, compatibility, stress, concurrency/race, and backup/restore integrity test coverage.
- `Makefile`, `Dockerfile`, `docker-compose.yml`
  - Standardized local/CI workflows for lint/build/test/verify and container-based deployment paths.

### Security

- Enforced SigV4-signed request authentication and policy-aware authorization across protected S3 routes.
- Added TLS operation modes (self-signed, manual certs, ACME DNS) and runtime security checks for safer deployment defaults.

[Unreleased]: https://github.com/jsco2t/storas/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/jsco2t/storas/releases/tag/v0.1.3
[0.1.2]: https://github.com/jsco2t/storas/releases/tag/v0.1.2
[0.1.1]: https://github.com/jsco2t/storas/releases/tag/v0.1.1
[0.1.0]: https://github.com/jsco2t/storas/releases/tag/v0.1.0
