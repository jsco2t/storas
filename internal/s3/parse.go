package s3

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

var ErrInvalidRequestPath = errors.New("invalid s3 request path")

type AddressingStyle string

const (
	AddressingPathStyle          AddressingStyle = "path"
	AddressingVirtualHostedStyle AddressingStyle = "virtual_hosted"
)

type RequestTarget struct {
	Style  AddressingStyle
	Bucket string
	Key    string
}

func ParseRequestTarget(r *http.Request, serviceHost string) (RequestTarget, error) {
	host := normalizeHost(r.Host)
	serviceHost = normalizeHost(serviceHost)

	path := strings.TrimPrefix(r.URL.Path, "/")

	if serviceHost != "" && strings.HasSuffix(host, "."+serviceHost) {
		bucket := strings.TrimSuffix(host, "."+serviceHost)
		if !IsValidBucketName(bucket) {
			return RequestTarget{}, ErrInvalidRequestPath
		}
		return RequestTarget{Style: AddressingVirtualHostedStyle, Bucket: bucket, Key: path}, nil
	}

	if path == "" {
		return RequestTarget{Style: AddressingPathStyle}, nil
	}
	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]
	if !IsValidBucketName(bucket) {
		return RequestTarget{}, ErrInvalidRequestPath
	}
	key := ""
	if len(parts) > 1 {
		key = parts[1]
	}
	return RequestTarget{Style: AddressingPathStyle, Bucket: bucket, Key: key}, nil
}

func ParseDispatchQuery(q map[string][]string) DispatchQuery {
	return DispatchQuery{
		ListType:         firstQuery(q, "list-type"),
		HasListType:      hasQuery(q, "list-type"),
		HasVersions:      hasQuery(q, "versions"),
		HasVersioning:    hasQuery(q, "versioning"),
		HasPolicy:        hasQuery(q, "policy"),
		HasPolicyStatus:  hasQuery(q, "policyStatus"),
		HasLifecycle:     hasQuery(q, "lifecycle"),
		HasACL:           hasQuery(q, "acl"),
		Delimiter:        firstQuery(q, "delimiter"),
		Prefix:           firstQuery(q, "prefix"),
		Continuation:     firstQuery(q, "continuation-token"),
		MaxKeys:          firstQuery(q, "max-keys"),
		HasUploads:       hasQuery(q, "uploads"),
		HasUploadID:      hasQuery(q, "uploadId"),
		HasPartNumber:    hasQuery(q, "partNumber"),
		UploadID:         firstQuery(q, "uploadId"),
		PartNumber:       firstQuery(q, "partNumber"),
		KeyMarker:        firstQuery(q, "key-marker"),
		UploadIDMarker:   firstQuery(q, "upload-id-marker"),
		MaxUploads:       firstQuery(q, "max-uploads"),
		PartNumberMarker: firstQuery(q, "part-number-marker"),
		MaxParts:         firstQuery(q, "max-parts"),
		HasCopySource:    hasQuery(q, "x-amz-copy-source"),
	}
}

func firstQuery(q map[string][]string, key string) string {
	if values, ok := q[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func hasQuery(q map[string][]string, key string) bool {
	_, ok := q[key]
	return ok
}

func normalizeHost(value string) string {
	host := strings.TrimSpace(value)
	if host == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
