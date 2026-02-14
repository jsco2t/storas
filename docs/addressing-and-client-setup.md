# Addressing Styles And Client Setup

`storas` supports both path-style and virtual-hosted-style addressing.

## Path-style

`http://host:9000/<bucket>/<key>`

Example:

```text
http://storage.local:9000/backup-a/dir/file.txt
```

## Virtual-hosted-style

`http://<bucket>.host:9000/<key>`

Example:

```text
http://backup-a.storage.local:9000/dir/file.txt
```

## AWS SDK for Go v2 example

```go
cfg, _ := config.LoadDefaultConfig(ctx,
  config.WithRegion("us-west-1"),
  config.WithBaseEndpoint("http://127.0.0.1:9000"),
)
client := s3.NewFromConfig(cfg, func(o *s3.Options) {
  o.UsePathStyle = true
})
```

## `rclone` endpoint setup

Use `provider = AWS`, static credentials, custom endpoint, and `force_path_style = true`.
Full tested config: `docs/compatibility-testing.md`.
