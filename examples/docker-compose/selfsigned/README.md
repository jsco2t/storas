# Self-Signed TLS Compose Stack

This stack runs `storas` over HTTPS with auto-generated self-signed certificates on `127.0.0.1:9443`.

## What this stack does

- Starts one `storas` container with `tls.mode=self_signed`.
- Binds service endpoint to host port `9443`.
- Persists object data in a Docker named volume (`storas-data`).
- Uses local config and authorization files from this directory.

## Setup environment file

Create a local `.env` from the example file:

```bash
cd examples/docker-compose/selfsigned
cp .env.example .env
```

Edit `.env` and set `STORAS_IMAGE` to a real image tag.

## Run

```bash
docker compose --env-file .env up -d
```

## Verify

```bash
curl -kfsS https://127.0.0.1:9443/healthz
curl -kfsS https://127.0.0.1:9443/readyz
```

Use `-k` in clients that do not trust self-signed certificates.

## Stop

```bash
docker compose down
```

Use `docker compose down -v` to also remove the `storas-data` volume.
