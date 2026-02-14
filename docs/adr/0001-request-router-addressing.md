# ADR 0001: Request Router And S3 Addressing Resolution

- Status: Accepted
- Date: 2026-02-13

## Context

The service must support both S3 path-style and virtual-hosted-style addressing,
with consistent operation resolution across both forms.

## Decision

Use a single HTTP router with a shared S3 handler path. Resolve bucket/key by:

- Virtual-hosted-style first when host is `<bucket>.<base-host>`.
- Path-style fallback using `/<bucket>/<key...>`.
- Unified operation dispatch on normalized `(method, query, bucket, key)`.

## Consequences

- One dispatch path prevents behavior drift between addressing styles.
- Bucket/key parsing is centralized and testable in isolation.
- Future operation additions only extend dispatcher mappings.
