package storage

import "errors"

var (
	ErrInvalidBucketName            = errors.New("invalid bucket name")
	ErrNoSuchBucket                 = errors.New("no such bucket")
	ErrNoSuchBucketPolicy           = errors.New("no such bucket policy")
	ErrNoSuchKey                    = errors.New("no such key")
	ErrNoSuchLifecycleConfiguration = errors.New("no such lifecycle configuration")
	ErrBucketExists                 = errors.New("bucket already exists")
	ErrBucketNotEmpty               = errors.New("bucket not empty")
	ErrEntityTooLarge               = errors.New("entity too large")
	ErrInvalidRange                 = errors.New("invalid range")
	ErrNoSuchUpload                 = errors.New("no such upload")
	ErrNoSuchVersion                = errors.New("no such version")
	ErrInvalidPart                  = errors.New("invalid part")
	ErrInvalidPartOrder             = errors.New("invalid part order")
	ErrInvalidRequest               = errors.New("invalid request")
	ErrInvalidVersionID             = errors.New("invalid version id")
	ErrBadDigest                    = errors.New("bad digest")
)
