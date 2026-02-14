# Developer Documentation

This directory is the onboarding and working reference for engineers building
`storas`.

`storas` is a single-node, filesystem-backed object storage service with an
S3-compatible API.

## Read This First

1. `docs/development/codebase-map.md`
2. `docs/development/s3-compatibility.md`
3. `docs/development/testing-and-ci.md`
4. `docs/development/decisions-and-scope.md`

## Quick Development Workflow

1. Run lint:
   - `NPM_CONFIG_CACHE=.cache/npm make lint`
2. Build the binary:
   - `make build`
3. Run the main test suite:
   - `make test`
4. Run integration and compatibility suites when your change touches request
   routing, API behavior, storage semantics, auth, policy, multipart, or
   interoperability:
   - `make test-integration`
   - `make test-compat`
5. Run full verification before major merges:
   - `NPM_CONFIG_CACHE=.cache/npm make verify`

## Local Run

1. Start with sample config:
   - `make dev`
2. Default endpoint:
   - `http://127.0.0.1:9000`
3. Health probes:
   - `GET /healthz`
   - `GET /readyz`

## Related Operator Docs

- `README.md`
- `docs/s3-support.md`
- `docs/configuration-reference.md`
- `docs/authorization-model.md`
- `docs/addressing-and-client-setup.md`
- `docs/compatibility-testing.md`
- `docs/s3-conformance-gap.md`
