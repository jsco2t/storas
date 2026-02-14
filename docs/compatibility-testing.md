# Compatibility Testing

Compatibility suites are in `test/compat/`.

## Commands

- Run all compatibility tests: `make test-compat`
- Run AWS SDK suite only: `make test-compat-aws`
- Run `rclone` suite only: `make test-compat-rclone`

All commands are non-interactive and suitable for CI.

## Covered compatibility workflows

- Core bucket/object lifecycle
- Authorization success/failure behavior
- ACL compatibility:
  - canned ACL request headers (`x-amz-acl`) on put/multipart create paths
  - ACL endpoint compatibility calls (`GetBucketAcl`, `GetObjectAcl`)
- Multipart upload lifecycle:
  - create upload
  - upload parts
  - list multipart uploads/parts
  - complete upload
  - abort upload
- Bucket lifecycle configuration API compatibility:
  - `PutBucketLifecycleConfiguration`
  - `GetBucketLifecycleConfiguration`
  - `DeleteBucketLifecycle`

## ACL compatibility matrix

| Tool | Version source | ACL-related coverage | Outcome |
| --- | --- | --- | --- |
| AWS SDK for Go v2 (`github.com/aws/aws-sdk-go-v2/service/s3`) | `go.mod` pinned module version | `PutObject` with canned ACL, `CreateMultipartUpload` with canned ACL, `GetBucketAcl`, `GetObjectAcl` | Pass |
| `rclone` S3 backend | `rclone` binary in test environment (`PATH`) | runtime config `acl = private` and explicit `--s3-acl private` transfer flows | Pass |

## ACL release gate

Merges that modify S3 compatibility behavior must keep both compatibility suites
green (`make test-compat`) and retain ACL coverage for AWS SDK v2 and `rclone`
flows so ACL model absence does not block target clients.

## Exact `rclone` config used by tests

```ini
[storas]
type = s3
provider = AWS
env_auth = false
access_key_id = AKIAFULL
secret_access_key = secret-full
region = us-west-1
endpoint = <compat test base URL>
acl = private
force_path_style = true
no_check_bucket = true
```

In tests this file is generated at runtime as `rclone.conf` and passed via `--config`.
