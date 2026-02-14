# Stress And Concurrency Testing

Stress and concurrency suites are implemented with Go's test tooling only and
are intentionally opt-in.

Default test targets stay unchanged:

- `make test`
- `make verify`

These commands do not execute stress suites.

## Opt-in local commands

Preferred make targets:

```bash
make test-stress
make test-race-concurrency
```

Stress tuning options:

- `STRESS_TEST_REPEAT` (default `1`)
- `STRESS_TEST_TIMEOUT` (default `20m`)
- `STRESS_TEST_RUN` (optional `-run` filter)
- `STRESS_TEST_PACKAGES` (default `./internal/storage ./internal/api ./test/stress`)

Run all stress suites:

```bash
make test-stress
```

Run stress suites with race detection and repeat count:

```bash
STRESS_TEST_REPEAT=3
make test-race-concurrency
```

## CI command pattern

Use an explicit opt-in CI job that is separate from default verification:

```bash
STRESS_TEST_REPEAT=3 make test-race-concurrency
```

## Coverage focus

The opt-in suites cover:

- high-contention API and storage mixed workloads
- metadata and payload consistency invariants
- version integrity under concurrent writes/deletes
- multipart list/truncation semantics and cleanup behavior
- cancellation/disconnect fault scenarios using standard Go HTTP/client primitives
