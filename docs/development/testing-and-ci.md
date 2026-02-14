# Testing And CI

This document explains how quality gates are structured and which suites you
should run for different change types.

## Test Layers

## Unit Tests (`internal/*`, `cmd/*`)

Focus:

- function/package behavior
- parser/validator correctness
- error mapping
- concurrency-sensitive storage/API internals

Typical files:

- `internal/api/service_test.go`
- `internal/storage/fs_test.go`
- `internal/storage/multipart_test.go`
- `internal/policy/policy_test.go`
- `internal/sigv4/*_test.go`
- `cmd/storas/main_test.go`

## Integration Tests (`test/integration`)

Focus:

- end-to-end behavior against in-process service
- multi-operation flows
- storage invariants and recovery

Notable files:

- `test/integration/service_integration_test.go`
- `test/integration/backup_restore_integration_test.go`

## Compatibility Tests (`test/compat`)

Focus:

- real client interoperability

Suites:

- `TestAWSSDKCompatibilitySuite`:
  - `test/compat/aws_sdk_compat_test.go`
- `TestRcloneCompatibilitySuite`:
  - `test/compat/rclone_compat_test.go`

Compatibility harness:

- `test/integration/compat_env.go`

## Stress And Race Tests (`test/stress`, selected `internal/*` tests)

Focus:

- high-contention correctness
- cancellation/disconnect resilience
- race detection

Gating:

- build tag `stress`
- explicit make targets only

## Build System Of Record

Use Makefile targets, not ad-hoc commands, whenever possible.

Core targets:

- `make lint`
- `make build`
- `make test`
- `make test-integration`
- `make test-compat`
- `make verify`

Additional targets:

- `make test-compat-aws`
- `make test-compat-rclone`
- `make test-stress`
- `make test-race-concurrency`
- `make test-restore-integrity`

If markdown lint hits host npm cache permissions, use:

- `NPM_CONFIG_CACHE=.cache/npm make lint`

## CI Workflow

Pipeline file:

- `.github/workflows/ci.yml`

Jobs:

1. `lint-build-test`
   - test update guard script
   - lint
   - build
   - unit test suite
2. `integration`
   - `make test-integration`
3. `compat-aws-sdk`
   - `make test-compat-aws`
4. `compat-rclone`
   - install `rclone`
   - print `rclone version`
   - `make test-compat-rclone`

## How To Choose What To Run

1. Docs-only change:
   - `NPM_CONFIG_CACHE=.cache/npm make lint-md`
2. Small internal logic change in one package:
   - `make lint`
   - `make build`
   - `make test`
3. API, auth, policy, storage, or router changes:
   - `make lint`
   - `make build`
   - `make test`
   - `make test-integration`
   - `make test-compat`
4. Concurrency-sensitive changes:
   - include `make test-stress`
   - include `make test-race-concurrency`
5. Broad or release-branch changes:
   - `NPM_CONFIG_CACHE=.cache/npm make verify`

## Adding New Tests

Guidelines used in this repository:

- Add tests when behavior changes, edge cases are introduced, or regressions are
  plausible.
- Prefer deterministic tests over timing-sensitive tests.
- Use `t.TempDir()` and scoped fixtures to avoid persistent artifacts.
- For new S3 features, prefer:
  - unit tests for parse/validation and backend semantics
  - integration tests for API contract
  - compatibility tests when client interop could diverge
