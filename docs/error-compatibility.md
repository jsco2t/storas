# Error Compatibility Coverage

Implemented S3-style error mapping includes:

- `AccessDenied`
- `InvalidAccessKeyId`
- `SignatureDoesNotMatch`
- `RequestTimeTooSkewed`
- `RequestTimeout`
- `NoSuchBucket`
- `NoSuchBucketPolicy`
- `NoSuchKey`
- `NoSuchUpload`
- `BucketAlreadyOwnedByYou`
- `BucketNotEmpty`
- `InvalidBucketName`
- `EntityTooLarge`
- `InvalidRange`
- `InvalidPart`
- `InvalidPartOrder`
- `BadDigest`
- `InvalidRequest`
- `IllegalLocationConstraintException`
- `MethodNotAllowed`
- `InternalError`

## Known edge cases

- Internal parsing/storage failures map to `InternalError`.
- Request cancellation/timeouts map to `RequestTimeout`.
- `PutObject`/`UploadPart` `Content-MD5` mismatches map to `BadDigest`.
- Unsupported request patterns outside MVP operation set return `MethodNotAllowed`.
- `CopyObject` source parsing rejects malformed encodings and unsupported query
  parameters with `InvalidRequest`.
