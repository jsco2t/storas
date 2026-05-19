# Reviewer 6: Constant & DRY Consistency

**Scope**: All tracked `.go` files across `/cmd/`, `/internal/`, `/test/`
**Date**: 2026-05-19

## Examination Summary

Examined all string literals used in `os.Getenv()`, URL paths, HTTP headers, S3 API keys, config keys, and query parameters for duplication or the potential to be consolidated into a single source of truth.

### Configuration Constants
- All config defaults defined in `internal/config/config.go` constants block (lines 14-22): `DefaultRegion`, `DefaultListenAddr`, `DefaultLogFormat`, etc. ✅
- TLS mode names stored in `allowedTLSModes` map, not duplicated as magic strings ✅
- Health check path defaults: `DefaultHealthLive`, `DefaultHealthReady` — used consistently via `config.DefaultHealthLive`, `config.DefaultHealthReady` ✅

### S3 API Query Parameter Keys
Query key strings used in `internal/s3/parse.go` and `internal/api/service.go`:
- `"list-type"`, `"versioning"`, `"policy"`, `"lifecycle"`, `"acl"`, `"uploadId"`, `"partNumber"` — all consistently defined in the single `ParseDispatchQuery()` factory function (parse.go:54-79) ✅

### S3 XML Namespace
- `s3XMLNamespace` defined as constant in `internal/api/service.go:33`: `"http://s3.amazonaws.com/doc/2006-03-01/"` — used consistently via single-source-of-truth string comparison (`cfg.XMLNamespace == s3XMLNamespace`) ✅

### HTTP Header Names
S3-related header strings (e.g. `"X-Amz-Copy-Source"`, `"x-amz-meta-"`, `"x-amz-version-id"`) — these are S3 protocol standards with no project-level constants available to consolidate. Usage is consistent across dispatch.go, service.go, and runtime/server.go ✅

### Service/Region Names
- Region passed as `cfg.Server.Region` from config throughout ✅
- Service name `"s3"` defined in main.go:83 — this is a S3 protocol identifier, not a project constant. No other services exist in the codebase so consolidation is unnecessary ✅

### Magic Numbers
- `1000` (MaxKeys default) appears at service.go:997, 1276, 1588 — used identically as the S3 API max-keys limit. These three occurrences are correct because they're in different handler functions handling similar S3 APIs. Consolidating into `const defaultMaxKeys = 1000` would be cosmetic and is flagged at lower confidence:
  - service.go:997 (handleListObjectsV2)
  - service.go:1276 (handleListObjectVersions)  
  - service.go:1588 (handleListMultipartUploads)

| Finding | Confidence | Severity |
|---------|-----------|----------|
| `1000` as magic number for max-keys default appears in 3 handlers | 70 | Low |

This is rated at confidence 70 — below the ≥ 80 reporting threshold — because: (a) it's a well-known S3 API constant, not a project-specific magic value; (b) each handler independently enforces its own limit which improves readability; (c) changing it would require coordination across handlers that are not necessarily modified together.

---

**Finding: None at confidence ≥ 80.** No duplicated string literals or config keys found in error messages, SQL queries, API paths, or configuration keys. The codebase is clean on this dimension.
