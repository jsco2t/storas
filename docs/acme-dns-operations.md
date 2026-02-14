# ACME DNS Operations

## Overview

`storas` ACME mode (`tls.mode: acme_dns`) performs real DNS-01 issuance and
renewal. The current provider implementation is Cloudflare.

Core flow:

1. Load ACME account key from state, or create it if missing.
2. Create ACME order for `tls.acme_dns.domain` using `tls.acme_dns.directory_url`.
3. Resolve DNS-01 authorization challenges.
4. Create `_acme-challenge` TXT records through the provider API.
5. Wait for DNS propagation (`propagation_timeout_seconds`, optional `resolvers`).
6. Finalize order and write issued certificate artifacts.
7. Serve certificates with automatic renewal scheduled from certificate expiry.

## Provider API Model

The provider interface is in `internal/tls/acme` and uses:

- `Present(ctx, fqdn, value, ttl)`
- `Cleanup(ctx, fqdn, value)`

Provider is selected by `tls.acme_dns.provider`.

Currently supported provider:

- `cloudflare`

## Required Credentials

Credentials are loaded only from environment variables prefixed by
`tls.acme_dns.credentials.env_prefix`.

Cloudflare requires:

- `<ENV_PREFIX>API_TOKEN`

Example:

- `env_prefix: STORAS_ACME_`
- environment variable: `STORAS_ACME_API_TOKEN`

## State Paths

ACME artifacts are persisted under:

- `${storage.data_dir}/system/acme/<domain>/`

Files:

- `account.key.pem`: ACME account key.
- `tls.key.pem`: active TLS private key.
- `tls.cert.pem`: active TLS certificate chain.

## Renewal Behavior

Renewal scheduling is computed from certificate `NotAfter` using:

- `tls.acme_dns.renew_before_seconds`

If renewal fails:

- the server keeps serving the last valid certificate,
- retries are applied with backoff and jitter,
- logs are emitted without secret/private-key leakage.

## Operational Runbook

### Startup validation failures

- Missing token: verify `<ENV_PREFIX>API_TOKEN` is set in the runtime environment.
- Unsupported provider: verify `tls.acme_dns.provider` value.
- DNS propagation timeout: increase `propagation_timeout_seconds` and/or set
  explicit resolvers in `tls.acme_dns.resolvers`.

### Renewal failures

1. Confirm provider credentials are still valid.
2. Confirm `_acme-challenge` TXT records can be created in the target zone.
3. Verify ACME directory endpoint (`directory_url`) is reachable.
4. Check propagation behavior from configured resolvers.
5. Confirm state path is writable and persisted across restarts.
