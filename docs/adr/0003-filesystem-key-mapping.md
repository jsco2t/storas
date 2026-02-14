# ADR 0003: Filesystem Key Mapping

- Status: Accepted
- Date: 2026-02-13

## Context

S3 keys can contain arbitrary UTF-8 bytes and path-like separators. Filesystem
storage must be safe, deterministic, and reversible.

## Decision

Use a deterministic reversible encoding for object keys before filesystem
materialization. Persist encoded payload and metadata sidecar paths under
bucket-specific namespaces.

## Consequences

- Prevents path traversal and separator ambiguity.
- Enables consistent key round-tripping.
- Requires dedicated encoding/decoding tests and migration care.
