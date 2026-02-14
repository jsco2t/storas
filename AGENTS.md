# STÒRAS Project Working Agreement

## Project Overview

`storas` is a Go-based, single-node, home-lab object storage service
that exposes an S3-compatible API and stores data on a local filesystem
backend.

Primary goals:

- S3 API compatibility sufficient for common third-party tools (for
  example `rclone` and AWS SDK-based clients).
- Simple, file-based configuration and authorization.
- Operational simplicity for home-lab deployment, including container-first workflows.

## Build System Of Record

The official build system for this repository is `make` via the
project `Makefile`.

Use `make` targets for common engineering workflows instead of ad-hoc
commands whenever an equivalent target exists.

Minimum expected targets:

- `make lint`
- `make build`
- `make test`
- `make test-integration`
- `make test-compat`
- `make test-stress`
- `make test-race-concurrency`
- `make test-restore-integrity`
- `make verify`
- `make build-container`

### Tooling Note

If markdown linting fails due host-level npm cache permission issues, run
make targets with a workspace-local cache override:

`NPM_CONFIG_CACHE=.cache/npm make verify`

## Completion Criteria For Coding Tasks

Before a coding task is considered complete, all of the following must be true:

- Code is linted.
- Code builds without warnings or errors.
- All tests pass.
- If non-trivial code changes were made, add or update tests for the
  changed/added behavior.

## Completion Criteria For Documentation Tasks

Before a documentation task is considered complete, markdown must be linted.

Documentation must be kept in sync with code changes:

- Update `README.md` when behavior, commands, or scope boundaries change.
- Update relevant files under `docs/` in the same change when implementation,
  compatibility, operations, or testing behavior changes.

## Task Planning Documents

Use the split task-plan format for this repo:

- Active task list:
  `.ai/plans/s3-compatible-object-store-tasks.md`
- Completed task archive:
  `.ai/plans/s3-compatible-object-store-completed-tasks.md`

When active tasks are fully completed, archive detailed history in the completed
document and keep the active document concise with current context, open gaps,
and next prioritized work.

## Golden Rule

DO NOT defer work without permission.

If work is deferred, the only acceptable way to do that is by creating
(or updating) a task document that clearly defines the scope and
breakdown of the deferred work.

The following are forbidden:

- Silent deferral.
- Deferral based on assumptions without explicit approval.
- Deferring work via hidden `TODO`/`LATER`/`BUG` style comments in code.
