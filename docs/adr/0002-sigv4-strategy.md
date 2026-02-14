# ADR 0002: SigV4 Implementation Strategy

- Status: Accepted
- Date: 2026-02-13

## Context

The service requires strict AWS Signature Version 4 support compatible with
common SDK and tooling behavior.

## Decision

Implement SigV4 verification in-house using a small dedicated package and
well-defined primitives:

- Parse authorization header and credential scope.
- Rebuild canonical request and string-to-sign deterministically.
- Verify HMAC signatures using constant-time comparisons.
- Support header-signed and presigned URL requests for compatibility targets.

## Consequences

- Fine-grained control over S3 compatibility edge cases.
- Clear unit-test seams for canonicalization and signature verification.
- Increased maintenance burden compared to a third-party verifier.
