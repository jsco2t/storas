# Docker Compose Examples

These examples run published `storas` container images from GHCR.

Available stacks:

- `http/`: HTTP on `127.0.0.1:9000`
- `selfsigned/`: HTTPS with self-signed cert on `127.0.0.1:9443`
- `acme-dns/`: HTTPS with ACME DNS automation on `127.0.0.1:9444`

For each stack:

1. Set `STORAS_IMAGE=ghcr.io/<github-owner>/storas:<tag>`.
2. `cd` into the stack directory.
3. Run `docker compose up -d`.
