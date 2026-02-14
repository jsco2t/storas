# S3 Compatibility Internals

This document explains where S3-compatible behavior is implemented and how to
extend it safely.

## Compatibility Philosophy

`storas` targets practical client interoperability over full AWS parity.

Current client targets:

- AWS SDK for Go v2
- `rclone`

Compatibility boundaries are tracked in:

- `docs/s3-support.md`
- `docs/s3-conformance-gap.md`
- `.ai/plans/s3-compatible-object-store-spec.md`

## Addressing Styles

Addressing is parsed in `internal/s3/parse.go`.

- Path style:
  - `http://host/<bucket>/<key>`
- Virtual-hosted style:
  - `http://<bucket>.<service-host>/<key>`

`ParseRequestTarget` determines the bucket/key tuple and routing style.

## Operation Resolution

Operation dispatch is centralized in `internal/s3/dispatch.go`.

- Method + query flags + selected headers -> `s3.Operation`.
- `internal/api/service.go` dispatches each operation to an explicit handler.

When adding an operation:

1. Add constant in `internal/s3/dispatch.go`.
2. Update resolution logic in `ResolveOperation`.
3. Add dispatch branch in `internal/api/service.go`.
4. Implement handler and storage backend method(s).
5. Map errors in `internal/s3err/errors.go`.
6. Add unit + integration + compatibility coverage as needed.

## SigV4 Compatibility

SigV4 is implemented in `internal/sigv4`.

- Parse auth:
  - `ParseRequestAuth` supports header and presigned query auth.
- Canonical request:
  - `BuildCanonicalRequest`.
- Scope/signature verification:
  - `ValidateScope`, `VerifyRequest`.
- Constant-time signature compare:
  - `VerifySignature`.
- Streaming payload mode:
  - `DecodeStreamingPayload` validates chunk signatures and returns decoded
    payload reader.

`internal/api/service.go` wires this in `authenticate`.

## Authorization Compatibility

Two layers are applied in API flow:

1. Static allow rules (`authorization.yaml`) via `internal/authz`.
2. Bucket policy evaluation via `internal/policy`.

Policy evaluation context is built from request attributes in
`policyEvaluationContextFromRequest` (`internal/api/service.go`), including
transport, source IP, headers, and S3/AWS-like condition keys.

## ACL Compatibility Model

ACL endpoints/headers are compatibility-only and intentionally do not provide a
full ACL authorization engine.

Implementation details:

- Header validation:
  - `validateACLCompatibilityHeaders` in `internal/api/service.go`.
- Endpoint handlers:
  - `handleGetBucketACL`, `handlePutBucketACL`,
    `handleGetObjectACL`, `handlePutObjectACL`.
- Behavior:
  - deterministic responses and accepted canned ACL headers for client
    compatibility.

## Bucket and Object API Support

Implemented operations are defined by the handler surface in
`internal/api/service.go` and backend contract in `internal/storage/storage.go`.

Major groups:

- Bucket:
  - list/create/delete/head
  - ACL compatibility endpoints
  - versioning (`GET/PUT ?versioning`)
  - policy (`GET/PUT/DELETE ?policy`, `GET ?policyStatus`)
  - lifecycle (`GET/PUT/DELETE ?lifecycle`)
- Object:
  - put/get/head/delete/copy
  - range requests
  - metadata and tagging headers
  - version-aware get/head/delete/list versions
- Multipart:
  - create/upload part/complete/abort
  - list multipart uploads/list parts

See `docs/s3-support.md` for the user-facing support matrix.

## Error Compatibility

Canonical S3 XML errors are defined in `internal/s3err/errors.go`.

- `MapError` translates internal errors to S3 API error codes.
- `Write` emits XML payload with `Code`, `Message`, `Resource`, and
  `RequestId`.

When adding new backend errors, map them explicitly to avoid accidental
`InternalError` responses.

## Storage-Semantic Compatibility

S3-like behavior is implemented in `internal/storage`.

- Bucket naming validation.
- Read-after-write semantics for object writes.
- ETag and metadata persistence.
- Version IDs and delete markers.
- Multipart manifest + ordered part checks.
- Lifecycle maintenance behavior.

ADR references:

- `docs/adr/0003-filesystem-key-mapping.md`
- `docs/adr/0005-metadata-etag.md`

## Known Intentional Gaps

These are deliberate scope boundaries for the current release:

- Full IAM-equivalent bucket policy parity is not complete.
- ACL authorization semantics are not implemented (compatibility-only behavior).
- Replication is not implemented.
- Lifecycle parity is partial for advanced AWS features.

Track current status in `docs/s3-conformance-gap.md`.
