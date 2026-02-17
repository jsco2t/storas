# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-17

### Added

- `cmd/`
  - Initial `storas` service entrypoint and startup wiring (`cmd/storas`).
- `internal/s3`, `internal/api`, `internal/storage`
  - Initial S3-compatible bucket/object API surface including core CRUD, multipart upload lifecycle, copy support, ACL compatibility endpoints/headers, versioning APIs, lifecycle configuration APIs, and bucket policy APIs.
- `internal/sigv4`, `internal/authz`, `internal/policy`
  - SigV4 request authentication, authorization engine integration, and bucket policy evaluation (including explicit deny handling and supported condition operator/key subsets).
- `internal/tls`, `internal/runtime`, `internal/config`, `internal/logging`
  - Runtime configuration loading/validation, HTTP server runtime/security controls, structured logging modes, and TLS support for self-signed, manual certificates, and ACME DNS-01 (Cloudflare provider path).
- `configs/`
  - Example configuration profiles for HTTP, self-signed TLS, ACME DNS, and authorization policy files.
- `docs/`, `docs/adr/`, `docs/development/`
  - Initial operator and developer documentation covering configuration, authorization model, S3 support boundaries, compatibility strategy, TLS operations, resiliency guidance, and architecture decisions.
- `test/`, `internal/**/*_test.go`
  - Unit, integration, compatibility, stress, concurrency/race, and backup/restore integrity test coverage.
- `Makefile`, `Dockerfile`, `docker-compose.yml`
  - Standardized local/CI workflows for lint/build/test/verify and container-based deployment paths.

### Security

- Enforced SigV4-signed request authentication and policy-aware authorization across protected S3 routes.
- Added TLS operation modes (self-signed, manual certs, ACME DNS) and runtime security checks for safer deployment defaults.

[Unreleased]: https://github.com/jsco2t/storas/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jsco2t/storas/releases/tag/v0.1.0
