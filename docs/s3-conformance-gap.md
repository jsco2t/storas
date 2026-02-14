# S3 Conformance Gap Analysis

Date: February 17, 2026

This document tracks meaningful gaps between current `storas` behavior and full
AWS S3 API parity.

## Executive Summary

Most previously identified protocol-fidelity gaps are now closed. Remaining
gaps are primarily intentional scope boundaries and phase-1 limitations, not
known regressions in implemented APIs.

## Tracking Contract

- This document is the source of truth for intentional S3 parity boundaries.
- The following boundaries must remain explicitly tracked here and in
  `docs/s3-support.md`:
  - bucket policy partial IAM parity
  - ACL compatibility-only behavior
  - lifecycle partial parity
  - replication out of scope
- Any newly discovered parity gap must be added with current behavior, AWS gap,
  impact, and priority.

## Resolved Since Prior Gap Review

The following items are now implemented and covered by tests:

- `ListBuckets` owner and `CreationDate` fields with AWS-compatible XML shape.
- `CreateBucket` location-constraint parsing and region mismatch error behavior.
- `DeleteObject` returns `NoSuchBucket` when bucket does not exist.
- ETag quoting and timestamp wire-format compatibility improvements.
- SigV4 streaming payload mode
  (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) with chunk-signature verification.
- ACL compatibility endpoints/headers for target client interoperability.
- Bucket versioning APIs plus object version-chain behavior.
- Bucket lifecycle configuration APIs and phase-1 execution worker.
- Bucket lifecycle phase-3 filter/predicate support for:
  `Filter.Tag`, `Filter.And` (`Prefix` + tag list + object-size predicates),
  top-level size predicates, and expiration by `Days` or absolute `Date`, with
  tag/size-aware sweep execution.
- Bucket policy CRUD/status APIs plus phase-1 evaluation enforcement.
- Bucket policy phase-2 condition support for:
  `Bool` (`aws:SecureTransport`),
  `IpAddress` / `NotIpAddress` (`aws:SourceIp`),
  and `StringEquals` / `StringNotEquals` over supported keys.
- Bucket policy phase-3 condition support for:
  `StringLike` / `StringNotLike`,
  `Null`,
  and extended request/principal keys (`aws:PrincipalArn`,
  `aws:PrincipalType`, `aws:userid`, `aws:username`, `s3:prefix`,
  `s3:delimiter`, `s3:max-keys`, `s3:VersionId`, `s3:x-amz-acl`).
- Bucket policy phase-4 condition support for:
  numeric operators (`NumericEquals`, `NumericNotEquals`,
  `NumericLessThan`, `NumericLessThanEquals`, `NumericGreaterThan`,
  `NumericGreaterThanEquals`) over `s3:max-keys` and
  `s3:signatureAge`, and date operators (`DateEquals`, `DateNotEquals`,
  `DateLessThan`, `DateLessThanEquals`, `DateGreaterThan`,
  `DateGreaterThanEquals`) over `aws:CurrentTime`.
- Bucket policy phase-5 condition-language support for:
  qualifier forms `ForAnyValue:` / `ForAllValues:` on
  `StringEquals` / `StringLike`, and `IfExists` suffix support for
  string/numeric/date operators.
- Bucket policy phase-6 condition support for ARN-native operators:
  `ArnEquals`, `ArnNotEquals`, `ArnLike`, `ArnNotLike` over
  `aws:PrincipalArn`, including qualified and `IfExists` forms where supported.
- Bucket policy principal parsing/evaluation improvements:
  `NotPrincipal` support, wildcard principal matching, and object principal
  set parsing (`AWS`, `CanonicalUser`, `Federated`, `Service`).
- Bucket policy condition-key coverage expansion:
  `aws:PrincipalAccount`, `s3:authType`, and `s3:signatureversion`.

## Current Remaining Gaps

## 1. Bucket policy support is phase-6 (partial IAM parity)

- Current behavior: bucket policy APIs are implemented
  (`GET/PUT/DELETE ?policy`, `GET ?policyStatus`) with per-bucket evaluation for
  bucket/object scoped requests and condition-aware enforcement for key
  transport/source-ip/header/principal/list-query use cases.
- Gap vs AWS S3: advanced IAM-compatible policy semantics are still not
  implemented (for example broad condition-key coverage, richer principal
  federation, and full policy language parity).
- Impact: complex AWS bucket policy documents are not fully portable.
- Priority: high (feature parity).

## 2. Replication is not implemented

- Current behavior: single-node local-filesystem backend only.
- Gap vs AWS S3: no cross-region replication, replication rules, or replication
  status semantics.
- Impact: DR and multi-site replication workflows are unavailable in-product.
- Priority: high (feature parity), intentionally out of scope for the initial
  `storas` release.
- Current operational guidance: use external redundancy/recovery controls (for
  example host-level RAID/ZFS/Btrfs, filesystem snapshots, and
  backup/restore runbooks).

## 3. ACL model is compatibility-only

- Current behavior: canned ACL compatibility behavior is supported for client
  interoperability; ACL APIs return deterministic compatibility responses.
- Gap vs AWS S3: no full ACL authorization semantics that alter effective access
  control.
- Impact: tooling that depends on ACLs for real authorization decisions will not
  behave like AWS.
- Priority: medium.

## 4. Lifecycle support is phase-3 (partial AWS lifecycle parity)

- Current behavior: lifecycle APIs and execution support prefix/tag/and filters,
  object-size predicates, and expiration by days/date for expiration,
  noncurrent expiration, and multipart abort.
- Gap vs AWS S3: advanced lifecycle capabilities remain out of scope (for
  example transition actions and full lifecycle filter/predicate parity).
- Impact: complex lifecycle policies are only partially portable.
- Priority: medium.

## Explicit Non-Goals For Current Release Scope

- Full IAM-compatible bucket policy condition/principal model.
- Full ACL authorization engine.
- Replication.

These boundaries are intentional and documented in `docs/s3-support.md`.

## Acceptance Signals For This Gap Document

- `make test`, `make test-integration`, and `make test-compat` remain green.
- `docs/s3-support.md` and this document stay aligned after behavior changes.
- Any newly discovered parity gap is added here with impact and priority.
