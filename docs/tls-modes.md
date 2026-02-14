# TLS Modes

## HTTP-only

Set:

```yaml
tls:
  enabled: false
```

## Self-signed

Set:

```yaml
tls:
  enabled: true
  mode: self_signed
  self_signed:
    common_name: localhost
    valid_days: 365
```

## Manual certificate files

Set:

```yaml
tls:
  enabled: true
  mode: manual
  cert_file: /etc/storas/tls/cert.pem
  key_file: /etc/storas/tls/key.pem
```

## ACME DNS (Cloudflare)

Set:

```yaml
tls:
  enabled: true
  mode: acme_dns
  acme_dns:
    email: ops@example.com
    directory_url: https://acme-v02.api.letsencrypt.org/directory
    provider: cloudflare
    domain: storage.example.com
    propagation_timeout_seconds: 120
    renew_before_seconds: 2592000
    resolvers: []
    credentials:
      env_prefix: STORAS_ACME_
```

Required environment variable:

- `STORAS_ACME_API_TOKEN`

Notes:

- Credentials are loaded only from environment variables.
- HTTP-01 challenge is not used.
- DNS-01 TXT records are created/deleted via the configured provider API.
- Certificate/account artifacts are persisted at `${storage.data_dir}/system/acme/<domain>/`.
- On startup, an existing valid certificate is reused; renewal is scheduled from cert expiry (`renew_before_seconds` safety window).
- Set `directory_url` to the Let's Encrypt staging endpoint for dry runs.
- Operational runbook: `docs/acme-dns-operations.md`.
