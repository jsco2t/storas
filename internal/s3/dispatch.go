package s3

import "net/http"

type Operation string

const (
	OperationUnknown                 Operation = "Unknown"
	OperationListBuckets             Operation = "ListBuckets"
	OperationCreateBucket            Operation = "CreateBucket"
	OperationDeleteBucket            Operation = "DeleteBucket"
	OperationHeadBucket              Operation = "HeadBucket"
	OperationGetBucketACL            Operation = "GetBucketAcl"
	OperationPutBucketACL            Operation = "PutBucketAcl"
	OperationGetBucketVersioning     Operation = "GetBucketVersioning"
	OperationPutBucketVersioning     Operation = "PutBucketVersioning"
	OperationGetBucketPolicy         Operation = "GetBucketPolicy"
	OperationPutBucketPolicy         Operation = "PutBucketPolicy"
	OperationDeleteBucketPolicy      Operation = "DeleteBucketPolicy"
	OperationGetBucketPolicyStatus   Operation = "GetBucketPolicyStatus"
	OperationGetBucketLifecycle      Operation = "GetBucketLifecycle"
	OperationPutBucketLifecycle      Operation = "PutBucketLifecycle"
	OperationDeleteBucketLifecycle   Operation = "DeleteBucketLifecycle"
	OperationListObjects             Operation = "ListObjectsV2"
	OperationListObjectVersions      Operation = "ListObjectVersions"
	OperationPutObject               Operation = "PutObject"
	OperationGetObject               Operation = "GetObject"
	OperationHeadObject              Operation = "HeadObject"
	OperationDeleteObject            Operation = "DeleteObject"
	OperationCopyObject              Operation = "CopyObject"
	OperationGetObjectACL            Operation = "GetObjectAcl"
	OperationPutObjectACL            Operation = "PutObjectAcl"
	OperationCreateMultipartUpload   Operation = "CreateMultipartUpload"
	OperationUploadPart              Operation = "UploadPart"
	OperationCompleteMultipartUpload Operation = "CompleteMultipartUpload"
	OperationAbortMultipartUpload    Operation = "AbortMultipartUpload"
	OperationListMultipartUploads    Operation = "ListMultipartUploads"
	OperationListParts               Operation = "ListParts"
)

type DispatchQuery struct {
	ListType         string
	HasListType      bool
	HasVersions      bool
	HasVersioning    bool
	HasPolicy        bool
	HasPolicyStatus  bool
	HasLifecycle     bool
	HasACL           bool
	Delimiter        string
	Prefix           string
	Continuation     string
	MaxKeys          string
	HasUploads       bool
	HasUploadID      bool
	HasPartNumber    bool
	UploadID         string
	PartNumber       string
	KeyMarker        string
	UploadIDMarker   string
	MaxUploads       string
	PartNumberMarker string
	MaxParts         string
	HasCopySource    bool
}

func ResolveOperation(method string, target RequestTarget, query DispatchQuery, headers http.Header) Operation {
	if target.Bucket == "" {
		if method == http.MethodGet {
			return OperationListBuckets
		}
		return OperationUnknown
	}

	if target.Key == "" {
		switch method {
		case http.MethodPut:
			if query.HasACL {
				return OperationPutBucketACL
			}
			if query.HasVersioning {
				return OperationPutBucketVersioning
			}
			if query.HasPolicy {
				return OperationPutBucketPolicy
			}
			if query.HasLifecycle {
				return OperationPutBucketLifecycle
			}
			return OperationCreateBucket
		case http.MethodDelete:
			if query.HasPolicy {
				return OperationDeleteBucketPolicy
			}
			if query.HasLifecycle {
				return OperationDeleteBucketLifecycle
			}
			return OperationDeleteBucket
		case http.MethodHead:
			return OperationHeadBucket
		case http.MethodGet:
			if query.HasACL {
				return OperationGetBucketACL
			}
			if query.HasVersioning {
				return OperationGetBucketVersioning
			}
			if query.HasPolicy {
				return OperationGetBucketPolicy
			}
			if query.HasPolicyStatus {
				return OperationGetBucketPolicyStatus
			}
			if query.HasLifecycle {
				return OperationGetBucketLifecycle
			}
			if query.HasUploads {
				return OperationListMultipartUploads
			}
			if query.HasVersions {
				return OperationListObjectVersions
			}
			if query.HasListType || query.ListType != "" {
				return OperationListObjects
			}
		}
		return OperationUnknown
	}

	switch method {
	case http.MethodPost:
		if query.HasUploads {
			return OperationCreateMultipartUpload
		}
		if query.HasUploadID {
			return OperationCompleteMultipartUpload
		}
		return OperationUnknown
	case http.MethodPut:
		if query.HasACL {
			return OperationPutObjectACL
		}
		if query.HasUploadID || query.HasPartNumber {
			if query.UploadID != "" && query.PartNumber != "" {
				return OperationUploadPart
			}
			return OperationUnknown
		}
		if headers.Get("X-Amz-Copy-Source") != "" || query.HasCopySource {
			return OperationCopyObject
		}
		return OperationPutObject
	case http.MethodGet:
		if query.HasACL {
			return OperationGetObjectACL
		}
		if query.HasUploadID {
			return OperationListParts
		}
		return OperationGetObject
	case http.MethodHead:
		return OperationHeadObject
	case http.MethodDelete:
		if query.HasUploadID {
			return OperationAbortMultipartUpload
		}
		return OperationDeleteObject
	default:
		return OperationUnknown
	}
}
