# Decisions And Scope

This document connects implementation choices in the codebase to ADRs and plan
documents, so new engineers can understand why behavior is shaped this way.

## ADRs

## ADR 0001: Request Router And Addressing

- File:
  - `docs/adr/0001-request-router-addressing.md`
- Why it matters:
  - Explains support for both path-style and virtual-hosted-style addressing.
  - Grounds routing and target parsing behavior in `internal/s3`.

## ADR 0002: SigV4 Strategy

- File:
  - `docs/adr/0002-sigv4-strategy.md`
- Why it matters:
  - Defines in-house SigV4 implementation boundaries.
  - Maps directly to `internal/sigv4` and auth flow in `internal/api`.

## ADR 0003: Filesystem Key Mapping

- File:
  - `docs/adr/0003-filesystem-key-mapping.md`
- Why it matters:
  - Explains encoded-key-on-filesystem model used by `internal/storage`.

## ADR 0004: TLS Automation

- File:
  - `docs/adr/0004-tls-automation.md`
- Why it matters:
  - Explains supported TLS modes and ACME DNS strategy.
  - Maps to `internal/runtime/server.go` and `internal/tls/acme`.

## ADR 0005: Metadata And ETag

- File:
  - `docs/adr/0005-metadata-etag.md`
- Why it matters:
  - Explains persisted metadata semantics and ETag behavior expected by clients.

## Plan And Spec Sources

## Core Specification

- `.ai/plans/s3-compatible-object-store-spec.md`

Use this for:

- goals vs non-goals
- MVP and release scope definitions
- acceptance criteria and testing strategy intent

## Active Task State

- `.ai/plans/s3-compatible-object-store-tasks.md`

Use this for:

- current open work
- current scope boundaries
- latest verification snapshot and command set

## Completed Work History

- `.ai/plans/s3-compatible-object-store-completed-tasks.md`

Use this for:

- rationale behind recently added behavior
- phase-by-phase compatibility and maintenance expansions
- why some decisions were sequenced as they were

## Intentional Scope Boundaries

These are currently intentional and should not be treated as accidental gaps:

- full IAM parity for bucket policy is not complete
- ACL model is compatibility-only, not full ACL authorization semantics
- replication is out of scope for current release
- lifecycle parity remains partial for advanced AWS features

Canonical tracking doc:

- `docs/s3-conformance-gap.md`

## How To Propose Scope Changes

1. Update or add an ADR for architectural changes.
2. Update `.ai/plans/s3-compatible-object-store-tasks.md` with explicit tasks.
3. Update user-facing docs:
   - `README.md`
   - `docs/s3-support.md`
   - `docs/s3-conformance-gap.md`
4. Add tests aligned with the expanded behavior.
5. Run verification targets from Makefile before merging.
