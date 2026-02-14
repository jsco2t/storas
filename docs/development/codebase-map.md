# Codebase Map

This document explains what each major package does and how a request flows
through the service.

## Top-Level Layout

- `cmd/storas`
  - Process entrypoint and startup orchestration.
- `internal/api`
  - S3 API handlers and protocol translation (HTTP/XML/headers/queries).
- `internal/s3`
  - Addressing parser, operation dispatcher, and request ID middleware.
- `internal/storage`
  - Filesystem backend and data model (objects, versions, multipart, lifecycle).
- `internal/authz`
  - Static authorization file loading and allow-rule checks.
- `internal/policy`
  - Bucket policy parser and evaluator.
- `internal/sigv4`
  - SigV4 parse/canonicalization/signature verification and streaming support.
- `internal/runtime`
  - HTTP/TLS server wiring, readiness/storage checks, auth file permission
    checks.
- `internal/tls/acme`
  - ACME DNS-01 certificate management (Cloudflare provider implemented).
- `internal/s3err`
  - Canonical S3 error mapping and XML error output.
- `test/`
  - Integration, compatibility, and stress suites.

## Request Lifecycle

1. Startup (`cmd/storas/main.go`)
   - Load and validate config.
   - Check auth file permissions and load `authorization.yaml`.
   - Ensure storage directory is writable.
   - Initialize `storage.FSBackend`.
   - Start multipart and lifecycle maintenance workers.
   - Build `api.Service` and pass handler to runtime server.
2. Server wiring (`internal/runtime/server.go`)
   - Configure plain HTTP or TLS mode (`manual`, `self_signed`, `acme_dns`).
   - Start `http.Server`.
3. Router and operation resolution (`internal/s3/router.go`,
   `internal/s3/parse.go`, `internal/s3/dispatch.go`)
   - Inject `X-Request-Id`.
   - Parse path-style or virtual-hosted target.
   - Resolve operation from method, query, and selected headers.
4. API pipeline (`internal/api/service.go`)
   - Apply body limits.
   - Authenticate SigV4 request.
   - Authorize against static authz rules, then bucket policy.
   - Dispatch to per-operation handler.
   - Map any error to S3 XML error response.
   - Emit structured request log.
5. Storage backend (`internal/storage/*.go`)
   - Execute operation on local filesystem with S3-compatible semantics.

## API Layer Responsibilities

`internal/api/service.go` is the highest-leverage file in the project.

- Auth and authz:
  - SigV4 verification (`authenticate`).
  - Action/resource mapping for authz rules.
  - Bucket policy context assembly and evaluation.
- Protocol translation:
  - XML encode/decode for list/multipart/lifecycle/versioning APIs.
  - Header/query parsing (`Range`, `versionId`, tagging, copy-source, ACL
    compatibility headers).
  - Content-MD5 validation for uploads.
  - Streaming SigV4 payload decode path.
- Dispatch surface:
  - Bucket APIs, object APIs, multipart APIs, versioning, policy, lifecycle.

## Storage Backend Responsibilities

The storage backend is implemented by `internal/storage/FSBackend`.

- Buckets:
  - Create/list/head/delete.
  - Bucket metadata in `bucket.json`.
  - Bucket policy in `bucket.policy.json`.
  - Bucket lifecycle in `bucket.lifecycle.json`.
  - Bucket versioning status persisted in bucket metadata.
- Objects:
  - Payload and metadata persistence.
  - Atomic write path using temp files + rename.
  - ETag and metadata persistence.
  - Range reads.
  - Copy object.
- Versioning:
  - Per-key version archives.
  - Delete marker handling.
  - Version listing with key/version markers.
  - Legacy object migration to `null` version when enabling versioning.
- Multipart:
  - Create/upload-part/complete/abort/list uploads/list parts.
  - Per-upload manifest + per-part metadata.
- Maintenance:
  - Stale multipart sweeps.
  - Lifecycle sweeps for expiration and multipart abort.

## Filesystem Data Model

For a bucket named `<bucket>` under `<data_dir>`:

- `buckets/<bucket>/objects/<encoded-key>.bin`
  - Current object payload.
- `buckets/<bucket>/meta/<encoded-key>.json`
  - Current object metadata.
- `buckets/<bucket>/versions/<encoded-key>/<encoded-version>.bin`
  - Versioned payload.
- `buckets/<bucket>/versions/<encoded-key>/<encoded-version>.json`
  - Versioned metadata.
- `buckets/<bucket>/multipart/<upload-id>/manifest.json`
  - Multipart upload manifest.
- `buckets/<bucket>/multipart/<upload-id>/part-<n>.bin`
  - Multipart part payload.
- `buckets/<bucket>/multipart/<upload-id>/part-<n>.json`
  - Multipart part metadata.
- `buckets/<bucket>/bucket.json`
- `buckets/<bucket>/bucket.policy.json`
- `buckets/<bucket>/bucket.lifecycle.json`

Keys and version IDs are encoded via URL-safe base64 in
`internal/storage/mapping.go`.

## Concurrency Model

- The backend uses `mutationMu` (`sync.RWMutex`) to serialize mutations and
  protect current/version metadata transitions.
- Reads generally use `RLock`; writes use `Lock`.
- Stress and race suites target these paths to detect ordering/collision bugs.

## Health and Readiness

- Router exposes configurable liveness and readiness endpoints.
- Readiness validates:
  - authz engine is loaded
  - storage data dir is writable
- Auth file is loaded once at startup; no runtime hot-reload.

## Where To Start For Common Changes

- Add/modify S3 operation behavior:
  - `internal/s3/dispatch.go`
  - `internal/api/service.go`
  - `internal/storage/storage.go`
  - `internal/storage/fs.go` or `internal/storage/multipart.go`
- Change auth/policy behavior:
  - `internal/authz/authz.go`
  - `internal/policy/policy.go`
  - policy context in `internal/api/service.go`
- Change request signing behavior:
  - `internal/sigv4/sigv4.go`
  - `internal/sigv4/verify.go`
- `internal/sigv4/streaming.go`
- Change TLS modes:
  - `internal/runtime/server.go`
  - `internal/tls/acme/*`
