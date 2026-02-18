# ACME DNS TLS Compose Stack

This stack runs `storas` over HTTPS with ACME DNS certificate management on `127.0.0.1:9444`.

## What this stack does

- Starts one `storas` container with `tls.mode=acme_dns`.
- Binds service endpoint to host port `9444`.
- Persists object data and ACME state in a Docker named volume (`storas-data`).
- Uses local config and authorization files from this directory.
- Expects provider credentials via `STORAS_ACME_API_TOKEN`.

## Before you run

Update `config.yaml` values under `tls.acme_dns`:

- `email`
- `provider`
- `domain`

## Setup environment file

Create a local `.env` from the example file:

```bash
cd examples/docker-compose/acme-dns
cp .env.example .env
```

Edit `.env` and set:

- `STORAS_IMAGE`
- `STORAS_ACME_API_TOKEN`

## Run

```bash
docker compose --env-file .env up -d
```

## Verify

```bash
curl -kfsS https://127.0.0.1:9444/healthz
curl -kfsS https://127.0.0.1:9444/readyz
```

Once ACME issuance completes, use your configured domain with a trusted TLS client.

## Stop

```bash
docker compose down
```

Use `docker compose down -v` to also remove persisted data and ACME state.
