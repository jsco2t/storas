# HTTP Compose Stack

This stack runs `storas` over plain HTTP on `127.0.0.1:9000` using a published GHCR image.

## What this stack does

- Starts one `storas` container.
- Binds service endpoint to host port `9000`.
- Persists object data in a Docker named volume (`storas-data`).
- Uses local config and authorization files from this directory.

## Setup environment file

Create a local `.env` from the example file:

```bash
cd examples/docker-compose/http
cp .env.example .env
```

Edit `.env` and set `STORAS_IMAGE` to a real image tag.

## Run

```bash
docker compose --env-file .env up -d
```

## Verify

```bash
curl -fsS http://127.0.0.1:9000/healthz
curl -fsS http://127.0.0.1:9000/readyz
```

## Stop

```bash
docker compose down
```

Use `docker compose down -v` to also remove the `storas-data` volume.
