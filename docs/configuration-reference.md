# Configuration Reference

`config.yaml` schema:

```yaml
server:
  listen_address: "0.0.0.0:9000"
  region: "us-west-1"
  log_format: "text" # text | json
  max_body_bytes: 26843545600
  max_header_bytes: 1048576
  trust_proxy_headers: false

storage:
  data_dir: "/var/lib/storas/data"
  multipart_maintenance:
    enabled: true
    startup_sweep: true
    sweep_interval_seconds: 300
    stale_after_seconds: 86400
    max_removals_per_sweep: 0
    remove_corrupt_uploads: true
    cleanup_temporary_files: true
    temp_file_stale_after_seconds: 3600
  lifecycle_maintenance:
    enabled: true
    startup_sweep: true
    sweep_interval_seconds: 300
    max_actions_per_sweep: 1000
    dry_run: false

auth:
  authorization_file: "/etc/storas/authorization.yaml"

tls:
  enabled: false
  mode: "self_signed" # self_signed | acme_dns | manual
  cert_file: ""
  key_file: ""

  self_signed:
    common_name: "localhost"
    valid_days: 365

  acme_dns:
    email: ""
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
    provider: "cloudflare"
    domain: ""
    propagation_timeout_seconds: 120
    renew_before_seconds: 2592000
    resolvers: []
    credentials:
      env_prefix: "STORAS_ACME_"

health:
  enabled: true
  path_live: "/healthz"
  path_ready: "/readyz"
```

## `server`

- `listen_address`: host:port bind address.
- `region`: SigV4 region scope.
- `log_format`: `text` or `json`.
- `max_body_bytes`: max object payload accepted (`<= 25 GiB`).
- `max_header_bytes`: max aggregate request header bytes accepted by the HTTP server.
- `trust_proxy_headers`: when `true`, policy source-IP evaluation prefers
  `X-Forwarded-For` / `X-Real-IP`; when `false`, source IP is taken from
  `RemoteAddr`.

## `storage`

- `data_dir`: filesystem root for bucket/object persistence.
- `multipart_maintenance.enabled`: enables stale multipart upload garbage
  collection.
- `multipart_maintenance.startup_sweep`: runs one stale upload sweep during
  startup before serving traffic.
- `multipart_maintenance.sweep_interval_seconds`: periodic sweep interval
  (seconds).
- `multipart_maintenance.stale_after_seconds`: minimum upload age (seconds)
  before removal.
- `multipart_maintenance.max_removals_per_sweep`: maximum number of uploads
  removed per sweep (`0` means no limit).
- `multipart_maintenance.remove_corrupt_uploads`: controls whether stale
  uploads with invalid/missing manifests are removed.
- `multipart_maintenance.cleanup_temporary_files`: remove stale multipart temp
  files (for example `part-*.tmp`) during sweep.
- `multipart_maintenance.temp_file_stale_after_seconds`: minimum age in seconds
  before temporary multipart files are removed.
- `lifecycle_maintenance.enabled`: enables lifecycle background execution.
- `lifecycle_maintenance.startup_sweep`: runs one lifecycle sweep on startup.
- `lifecycle_maintenance.sweep_interval_seconds`: lifecycle sweep interval in
  seconds.
- `lifecycle_maintenance.max_actions_per_sweep`: caps lifecycle actions per
  sweep across all buckets/rules (`0` means no limit).
- `lifecycle_maintenance.dry_run`: reports matched lifecycle actions without
  mutating stored objects/uploads.
- Lifecycle maintenance emits per-sweep aggregate and per-rule action logs
  (`matched_candidates`, `applied_actions`, skip counts) in both text/json log
  modes.

## `auth`

- `authorization_file`: path to `authorization.yaml`.
- `authorization_file` is read during startup and used to construct the
  in-memory authorization engine.
- Runtime hot-reload of `authorization.yaml` is not currently supported.
- Changing `authorization.yaml` requires a process restart before new rules are
  enforced.

## `tls`

- `enabled`: controls HTTP vs HTTPS startup.
- `mode`:
  - `self_signed`: runtime-generated dev certificate.
  - `manual`: loads `cert_file` and `key_file`.
  - `acme_dns`: ACME DNS-01 issuance/renewal (currently Cloudflare provider path).
- `cert_file`/`key_file`: required in `manual` mode.
- `self_signed.common_name`: certificate CN.
- `self_signed.valid_days`: validity period.
- `acme_dns.email`: ACME registration email.
- `acme_dns.directory_url`: ACME directory endpoint.
- `acme_dns.provider`: DNS provider (`cloudflare`).
- `acme_dns.domain`: certificate DNS name.
- `acme_dns.propagation_timeout_seconds`: DNS propagation wait budget.
- `acme_dns.renew_before_seconds`: renewal safety window (seconds before certificate expiry).
- `acme_dns.resolvers`: optional resolver override list.
- `acme_dns.credentials.env_prefix`: environment variable prefix for provider creds.
- Cloudflare credential key: `<env_prefix>API_TOKEN`.
- ACME state path: `${storage.data_dir}/system/acme/<domain>/` stores account key and issued cert/key material.
- ACME operations runbook: `docs/acme-dns-operations.md`.

## `health`

- `enabled`: enables liveness/readiness routes.
- `path_live`: liveness route path.
- `path_ready`: readiness route path.
