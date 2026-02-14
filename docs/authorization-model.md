# Authorization Model

Authorization is allow-only with deny-by-default behavior.

## Schema

```yaml
users:
  - name: "backup-agent"
    access_key: "AKIAEXAMPLEBACKUP"
    secret_key: "super-secret"
    allow:
      - action: "bucket:list"
        resource: "*"
      - action: "bucket:create"
        resource: "*"
      - action: "object:put"
        resource: "backup-*/*"
```

## Rule semantics

- A request is authorized only when at least one `allow` rule matches.
- No matching rule returns S3 `AccessDenied`.
- Bucket actions evaluate on bucket name.
- Object actions evaluate on `<bucket>/<key>`.
- `resource` uses glob-like matching.
- `CopyObject` requires `object:copy` on destination and `object:get` on source.

## Authorization file reload behavior

- `authorization.yaml` is loaded once during process startup.
- Runtime hot-reload is not currently supported.
- After updating `authorization.yaml`, restart `storas` to apply changes.
- If the service process is not restarted, prior in-memory rules remain active.

## Bucket policy interaction

- For bucket/object scoped requests, `authorization.yaml` is evaluated first.
- If `authorization.yaml` denies a request, bucket policy is not consulted.
- If a bucket policy exists:
  - explicit bucket-policy `Deny` overrides allow decisions,
  - a matching bucket-policy `Allow` is required for the request to proceed.
- Bucket-policy CRUD APIs are available via:
  - `GET ?policy`
  - `PUT ?policy`
  - `DELETE ?policy`
  - `GET ?policyStatus`
- Bucket-policy condition support includes:
  - operators: `Bool`, `IpAddress`, `NotIpAddress`, `StringEquals`,
    `StringNotEquals`, `StringLike`, `StringNotLike`, `Null`,
    `ArnEquals`, `ArnNotEquals`, `ArnLike`, `ArnNotLike`,
    `NumericEquals`, `NumericNotEquals`, `NumericLessThan`,
    `NumericLessThanEquals`, `NumericGreaterThan`,
    `NumericGreaterThanEquals`, `DateEquals`, `DateNotEquals`,
    `DateLessThan`, `DateLessThanEquals`, `DateGreaterThan`,
    `DateGreaterThanEquals`
  - qualifier prefixes:
    - `ForAnyValue` and `ForAllValues` for `StringEquals` and `StringLike`
  - `IfExists` suffix:
    - supported for string/numeric/date operators (unsupported on `Null`)
  - keys: `aws:SecureTransport`, `aws:SourceIp`, `aws:PrincipalArn`,
    `aws:PrincipalAccount`, `aws:PrincipalType`, `aws:userid`,
    `aws:username`, `s3:authType`, `s3:signatureversion`, `s3:prefix`,
    `s3:delimiter`, `s3:max-keys`, `s3:VersionId`, `s3:x-amz-acl`,
    `s3:RequestHeader/<Header-Name>`, `aws:CurrentTime`,
    `s3:signatureAge`
- Statement principal parsing supports `Principal` and `NotPrincipal`
  (mutually exclusive per statement), including wildcard matching and object
  forms for `AWS`, `CanonicalUser`, `Federated`, and `Service` principal sets.

## Supported actions

- `bucket:list`
- `bucket:create`
- `bucket:delete`
- `bucket:head`
- `object:list`
- `object:put`
- `object:get`
- `object:head`
- `object:delete`
- `object:copy`

## Least-privilege examples

Backup writer for `backup-*` buckets:

```yaml
users:
  - name: backup-writer
    access_key: AKIABACKUP
    secret_key: change-me
    allow:
      - action: bucket:list
        resource: "*"
      - action: object:put
        resource: "backup-*/*"
      - action: object:get
        resource: "backup-*/*"
```
