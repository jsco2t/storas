# Supported S3 API Scope

## Implemented operations

- `ListBuckets`
- `CreateBucket`
- `DeleteBucket`
- `HeadBucket`
- `ListObjectsV2`
- `PutObject`
- `GetObject`
- `HeadObject`
- `DeleteObject`
- `CopyObject`
- `CreateMultipartUpload`
- `UploadPart`
- `CompleteMultipartUpload`
- `AbortMultipartUpload`
- `ListMultipartUploads`
- `ListParts`
- `GetBucketAcl` / `PutBucketAcl` (compatibility responses only)
- `GetObjectAcl` / `PutObjectAcl` (compatibility responses only)
- `GetBucketVersioning` / `PutBucketVersioning` (bucket state only)
- `GetBucketPolicy` / `PutBucketPolicy` / `DeleteBucketPolicy`
- `GetBucketPolicyStatus`

`ListBuckets` behavior notes:

- Responses include stable owner fields and bucket `CreationDate` values.

`ListObjectsV2` behavior notes:

- `list-type=2` is required when using bucket listing query mode.
- `max-keys` supports `0..1000` (values above `1000` are clamped).
- Responses include `KeyCount` for returned object entries.
- With `delimiter`, `max-keys` limits the combined returned entries
  (`Contents` + `CommonPrefixes`) for truncation behavior.
- `start-after` is supported.
- `fetch-owner=true` is supported and includes stable owner fields in listed object entries.
- `continuation-token` takes precedence over `start-after` when both are sent.
- `encoding-type=url` is supported for list responses and key/prefix encoding.
- Conflicting duplicate query values (for example repeated keys with different
  values) are rejected with `InvalidRequest`.

`GetObject`/`HeadObject` behavior notes:

- `Accept-Ranges: bytes` is returned for object reads.
- Range responses return the selected range length in `Content-Length`.
- `If-Range` is supported; on mismatch the service returns the full object body.
- Objects without explicit content type default to
  `application/octet-stream`.
- `Content-MD5` is validated for `PutObject` and `UploadPart`.
- Oversized aggregate `x-amz-meta-*` user metadata is rejected with
  `InvalidRequest`.
- `x-amz-tagging` is parsed/validated on write paths and persisted for
  lifecycle-filter evaluation.
- ETag headers are returned as quoted values.

`CreateBucket` behavior notes:

- Optional `CreateBucketConfiguration` request bodies are parsed.
- `LocationConstraint` values must match the configured service region.

SigV4 payload support:

- `UNSIGNED-PAYLOAD` and fixed SHA-256 payload hash modes are supported.
- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` is supported with chunk-signature
  verification.

Multipart list behavior notes:

- `ListMultipartUploads` enforces S3 marker pairing rules:
  `upload-id-marker` requires `key-marker`.
- For `ListMultipartUploads`, `key-marker` without `upload-id-marker` skips all
  uploads whose key equals `key-marker`.
- `encoding-type=url` is supported for `ListMultipartUploads` and `ListParts`.
- Unsupported `x-amz-copy-source-if-*` conditional headers on `CopyObject`
  requests are rejected with `InvalidRequest`.

ACL compatibility behavior notes:

- `x-amz-acl` canned ACL headers are accepted as no-op compatibility hints for:
  - `CreateBucket`
  - `PutObject`
  - `CopyObject`
  - `CreateMultipartUpload`
- ACL grant headers (`x-amz-grant-*`) are rejected with deterministic
  `InvalidRequest` responses.
- ACL APIs return deterministic compatibility responses and do not alter
  authorization behavior.

Versioning behavior notes:

- `GET ?versioning` and `PUT ?versioning` are supported for bucket versioning
  state (`Enabled`/`Suspended`).
- Per-object version chains are supported for versioned buckets.
- `versionId` query handling is supported for:
  - `GetObject`
  - `HeadObject`
  - `DeleteObject`
- `ListObjectVersions` is supported for version history and delete marker
  discovery.
- `ListObjectsV2` only returns current object state (non-delete-marker current
  versions).

Lifecycle behavior notes:

- Bucket lifecycle configuration APIs are supported:
  - `GET ?lifecycle`
  - `PUT ?lifecycle`
  - `DELETE ?lifecycle`
- Phase-3 lifecycle rule schema support includes:
  - rule status (`Enabled` / `Disabled`)
  - filter forms:
    - `Filter.Prefix` and legacy `Prefix`
    - `Filter.Tag`
    - `Filter.And` (`Prefix` + `Tag` predicates + optional size predicates)
    - `Filter.ObjectSizeGreaterThan`
    - `Filter.ObjectSizeLessThan`
  - expiration days
  - expiration date (`Expiration.Date`)
  - noncurrent-version expiration days
  - abort-incomplete-multipart-upload days
- Lifecycle rule filter matching is conjunctive across configured
  prefix/tag/object-size predicates.
- Lifecycle background execution is implemented via
  `storage.lifecycle_maintenance`:
  - startup sweep + periodic sweeps
  - bounded actions per sweep
  - optional dry-run mode
  - tag-aware matching using persisted object tags (`x-amz-tagging`)
  - per-sweep aggregate audit logs plus per-rule bucket/rule/action/result
    counts

Bucket policy behavior notes:

- Bucket policy CRUD APIs are supported:
  - `GET ?policy`
  - `PUT ?policy`
  - `DELETE ?policy`
  - `GET ?policyStatus`
- Policies are stored as JSON documents and validated on write.
- Statement principal matching supports both `Principal` and `NotPrincipal`
  forms (mutually exclusive per statement).
- Bucket policy resources must target the same bucket as the request.
- Evaluation order for bucket/object scoped requests:
  - `authorization.yaml` allow rules are evaluated first.
  - if a bucket policy exists, explicit `Deny` wins.
  - if a bucket policy exists and no statement allows the request, the request
    is denied.
- Supported bucket policy condition operators and keys:
  - `Bool`:
    - `aws:SecureTransport`
  - `IpAddress` / `NotIpAddress`:
    - `aws:SourceIp`
  - `StringEquals` / `StringNotEquals`:
    - `aws:SecureTransport`
    - `aws:SourceIp`
    - `aws:PrincipalArn`
    - `aws:PrincipalAccount`
    - `aws:PrincipalType`
    - `aws:userid`
    - `aws:username`
    - `s3:authType`
    - `s3:signatureversion`
    - `s3:prefix`
    - `s3:delimiter`
    - `s3:max-keys`
    - `s3:VersionId`
    - `s3:x-amz-acl`
    - `s3:RequestHeader/<Header-Name>`
  - `StringLike` / `StringNotLike`:
    - `aws:SecureTransport`
    - `aws:SourceIp`
    - `aws:PrincipalArn`
    - `aws:PrincipalAccount`
    - `aws:PrincipalType`
    - `aws:userid`
    - `aws:username`
    - `s3:authType`
    - `s3:signatureversion`
    - `s3:prefix`
    - `s3:delimiter`
    - `s3:max-keys`
    - `s3:VersionId`
    - `s3:x-amz-acl`
    - `s3:RequestHeader/<Header-Name>`
  - `ArnEquals` / `ArnNotEquals` / `ArnLike` / `ArnNotLike`:
    - `aws:PrincipalArn`
  - `Null`:
    - same key-set as string operators above
  - `NumericEquals` / `NumericNotEquals` / `NumericLessThan` /
    `NumericLessThanEquals` / `NumericGreaterThan` /
    `NumericGreaterThanEquals`:
    - `s3:max-keys`
    - `s3:signatureAge`
  - `DateEquals` / `DateNotEquals` / `DateLessThan` / `DateLessThanEquals` /
    `DateGreaterThan` / `DateGreaterThanEquals`:
    - `aws:CurrentTime`
- Supported condition-operator qualifier forms:
  - `ForAnyValue:StringEquals`
  - `ForAllValues:StringEquals`
  - `ForAnyValue:StringLike`
  - `ForAllValues:StringLike`
  - `ForAnyValue:ArnEquals`
  - `ForAllValues:ArnEquals`
  - `ForAnyValue:ArnLike`
  - `ForAllValues:ArnLike`
- Supported `IfExists` condition-operator forms:
  - `String*IfExists` for supported string keys
  - `Arn*IfExists` for supported ARN keys
  - `Numeric*IfExists` for supported numeric keys
  - `Date*IfExists` for `aws:CurrentTime`
- Unsupported condition operators/keys are rejected with `InvalidRequest`.
- Source IP condition evaluation uses:
  - `RemoteAddr` by default
  - `X-Forwarded-For` / `X-Real-IP` when `server.trust_proxy_headers=true`
- Copy source authorization also enforces source bucket policy rules.

## Intentional parity boundaries

- Bucket policy support remains phase-6 and partial IAM parity.
- ACL behavior remains compatibility-only.
- Lifecycle support remains partial lifecycle parity (advanced transition actions
  remain out of scope).
- Replication remains out of scope for this release.
- Operational resiliency (backup/restore/redundancy) is operator-managed; see
  `docs/operational-resiliency.md`.
- Parity-gap tracking source of truth: `docs/s3-conformance-gap.md`.

## Explicit non-goals

- Full ACL authorization model.
- Object lock.
- Replication.
- Multi-node/distributed storage.
- External identity backends.
- Full IAM-compatible bucket policy condition language and principal federation.

## Client targets

- AWS SDK for Go v2 style usage.
- `rclone` S3 backend with custom endpoint.

## Bucket naming compatibility

- Bucket names use S3-style validation for lowercase DNS-compatible names.
- Dotted bucket names are supported (for example `logs.prod`).
- IP-address-style bucket names and invalid dot/hyphen label forms are rejected.
