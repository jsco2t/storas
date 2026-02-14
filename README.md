# stòras

`stòras` is a single-node, filesystem-backed object store with an S3-compatible API.

## Why The Name

`stòras` is a Scottish Gaelic word with meanings including store, treasure,
wealth, and resource. The project uses `stòras` as the product name and
`storas` for technical identifiers such as the Go module path, binary name, and
container paths.
Pronunciation (Scottish Gaelic): `/ˈst̪ɔːrəs/` (roughly "STOR-uhs").

## Quick start (local)

1. Ensure Go `1.25+` and `make` are installed.
2. Use sample config files from `configs/`.
3. Start the service:

```bash
make dev
```

Service endpoint defaults to `http://127.0.0.1:9000` with health endpoints:

- `GET /healthz`
- `GET /readyz`

## Container run

Build image:

```bash
make build-container
```

Run with compose:

```bash
docker compose up --build
```

The default compose target starts HTTP on `:9000`. Optional TLS variants use
profiles:

```bash
docker compose --profile selfsigned up --build
docker compose --profile acme up --build
```

Compose examples for HTTP, self-signed TLS, and ACME DNS are documented in
`docker-compose.yml` and `configs/`.
ACME mode requires `STORAS_ACME_API_TOKEN` and persists certificate state under
`${storage.data_dir}/system/acme/<domain>/`.

## Test commands

- `make lint`
- `make build`
- `make test`
- `make test-integration`
- `make test-compat`
- `make test-stress`
- `make test-race-concurrency`
- `make test-restore-integrity`
- `make verify`
- Opt-in stress tuning:
  `STRESS_TEST_REPEAT=2 STRESS_TEST_TIMEOUT=30m make test-stress`
- Opt-in race tuning:
  `STRESS_TEST_REPEAT=3 STRESS_TEST_TIMEOUT=30m make test-race-concurrency`

## Authorization file reload behavior

- `auth.authorization_file` is loaded once during process startup.
- Runtime hot-reload of `authorization.yaml` is not currently supported.
- After updating `authorization.yaml`, restart the `storas` process before the
  new rules take effect.
- Readiness checks confirm the in-memory authorization engine is available, but
  do not re-read the authorization file on each probe.
- Operational references:
  - `docs/configuration-reference.md`
  - `docs/authorization-model.md`

## Implemented S3 operations

- Bucket/object MVP operations
- Multipart upload lifecycle (`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`, `ListParts`)
- Multipart stale-upload maintenance (startup sweep + periodic garbage collection) via `storage.multipart_maintenance`, including sweep caps and temporary-file cleanup controls
- ACL compatibility endpoints and canned ACL header no-op handling for client interoperability (`Get*Acl`, `Put*Acl`, `x-amz-acl`)
- Bucket versioning APIs and object version chains:
  - bucket state APIs (`GET/PUT ?versioning`)
  - `versionId` support on `GetObject`, `HeadObject`, and `DeleteObject`
  - `ListObjectVersions` for per-key version history and delete markers
- Bucket lifecycle configuration APIs (`GET/PUT/DELETE ?lifecycle`) with
  validated phase-3 rule schema support:
  - `Filter.Prefix` and legacy `Prefix`
  - `Filter.Tag`
  - `Filter.And` (`Prefix` + `Tag` predicates + optional size predicates)
  - `Filter.ObjectSizeGreaterThan`
  - `Filter.ObjectSizeLessThan`
  - expiration by `Days` or absolute `Date`
- Bucket policy APIs (`GET/PUT/DELETE ?policy`, `GET ?policyStatus`) with
  JSON validation, per-bucket policy persistence, and phase-6 condition support
  (`Bool`, IP CIDR, string, ARN, wildcard, null, numeric, and date operators;
  qualified forms `ForAnyValue`/`ForAllValues`; and `IfExists`
  variants over supported keys including `aws:PrincipalArn`,
  `aws:CurrentTime`, and `s3:signatureAge`)
- Lifecycle execution worker for phase-3 lifecycle actions:
  - current-version expiration
  - noncurrent-version expiration
  - abort-incomplete-multipart-upload
  - filter-aware matching using persisted object tags and object-size predicates
  - bounded sweeps and dry-run support via `storage.lifecycle_maintenance`
  - per-sweep aggregate logging and per-rule action breakdown logs

## Current scope boundaries

- Bucket policy support is phase-6 and remains partial IAM parity.
- ACL behavior is compatibility-only and does not provide full ACL
  authorization semantics.
- Lifecycle support is phase-2 and remains partial parity for advanced
  lifecycle transitions.
- Replication is explicitly out of scope for this release.
- Built-in durability is single-node filesystem durability only; redundancy,
  backup, point-in-time restore, and disaster recovery are operator-managed.
- Full IAM-compatible bucket policy condition language/federated principals
  remain out of scope for this release.
- Gap tracking source of truth: `docs/s3-conformance-gap.md`.

## Documentation index

- Developer onboarding and code map: `docs/development/README.md`
- Config reference: `docs/configuration-reference.md`
- Authorization model: `docs/authorization-model.md`
- Supported operations and non-goals: `docs/s3-support.md`
- Addressing and client setup: `docs/addressing-and-client-setup.md`
- TLS modes: `docs/tls-modes.md`
- ACME DNS operations/runbook: `docs/acme-dns-operations.md`
- Error compatibility: `docs/error-compatibility.md`
- Compatibility suites and `rclone` config: `docs/compatibility-testing.md`
- Stress and concurrency suites: `docs/stress-testing.md`
- Operational resiliency runbook: `docs/operational-resiliency.md`
