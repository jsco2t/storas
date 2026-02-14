# ADR 0004: TLS Automation Strategy

- Status: Accepted
- Date: 2026-02-13

## Context

The service must support no-TLS operation, self-signed certificates for local
development, and automated ACME DNS challenge flows.

## Decision

Support three explicit TLS modes behind config validation:

- `self_signed` for local development certificate generation.
- `manual` for static cert/key file loading.
- `acme_dns` for DNS challenge automation using provider APIs, with provider
  credentials loaded from environment variables only.

For `acme_dns`, the implementation uses a provider registry + provider
interface (`Present`/`Cleanup`) and currently ships Cloudflare support.
ACME account/certificate artifacts are persisted under
`${storage.data_dir}/system/acme/<domain>/` so restart reuse is possible.
Renewal scheduling is certificate-expiry driven (`NotAfter` with
`renew_before_seconds`) and uses bounded backoff+jitter retries.

## Consequences

- Clear operational model per deployment environment.
- Strict startup validation catches misconfiguration early.
- ACME mode introduces external provider dependency and DNS propagation timing
  sensitivity.
- Existing valid certificates remain in service if renewal fails.
