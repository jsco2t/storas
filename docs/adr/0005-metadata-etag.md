# ADR 0005: Metadata Persistence And ETag Behavior

- Status: Accepted
- Date: 2026-02-13

## Context

S3-compatible object handlers require stable metadata and ETag behavior for
GET/HEAD/list flows and downstream client interoperability.

## Decision

Persist object metadata in sidecar documents adjacent to object payloads,
including content-type, content-length, last-modified, user metadata, and ETag.
For MVP, compute and persist ETag at write time and return it as authoritative
value for reads and object listings.

## Consequences

- Fast metadata retrieval without full payload reads.
- Enables consistent ETag response behavior across handlers.
- Requires atomic write coordination for payload and metadata commits.
