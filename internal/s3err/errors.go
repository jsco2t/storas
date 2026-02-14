package s3err

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"

	"storas/internal/s3"
	"storas/internal/sigv4"
	"storas/internal/storage"
)

type APIError struct {
	Code       string
	Message    string
	StatusCode int
}

func (e APIError) Error() string {
	return e.Code + ": " + e.Message
}

var (
	AccessDenied                       = APIError{Code: "AccessDenied", Message: "Access Denied", StatusCode: http.StatusForbidden}
	InvalidAccessKeyID                 = APIError{Code: "InvalidAccessKeyId", Message: "The AWS Access Key Id you provided does not exist in our records.", StatusCode: http.StatusForbidden}
	SignatureDoesNotMatch              = APIError{Code: "SignatureDoesNotMatch", Message: "The request signature we calculated does not match the signature you provided.", StatusCode: http.StatusForbidden}
	RequestTimeTooSkewed               = APIError{Code: "RequestTimeTooSkewed", Message: "The difference between the request time and the current time is too large.", StatusCode: http.StatusForbidden}
	RequestTimeout                     = APIError{Code: "RequestTimeout", Message: "Your socket connection to the server was not read from or written to within the timeout period.", StatusCode: http.StatusBadRequest}
	NoSuchBucket                       = APIError{Code: "NoSuchBucket", Message: "The specified bucket does not exist.", StatusCode: http.StatusNotFound}
	NoSuchBucketPolicy                 = APIError{Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist.", StatusCode: http.StatusNotFound}
	NoSuchKey                          = APIError{Code: "NoSuchKey", Message: "The specified key does not exist.", StatusCode: http.StatusNotFound}
	NoSuchUpload                       = APIError{Code: "NoSuchUpload", Message: "The specified multipart upload does not exist.", StatusCode: http.StatusNotFound}
	NoSuchVersion                      = APIError{Code: "NoSuchVersion", Message: "The specified version does not exist.", StatusCode: http.StatusNotFound}
	NoSuchLifecycleConfiguration       = APIError{Code: "NoSuchLifecycleConfiguration", Message: "The lifecycle configuration does not exist.", StatusCode: http.StatusNotFound}
	BucketAlreadyOwnedByYou            = APIError{Code: "BucketAlreadyOwnedByYou", Message: "Your previous request to create the named bucket succeeded and you already own it.", StatusCode: http.StatusConflict}
	BucketNotEmpty                     = APIError{Code: "BucketNotEmpty", Message: "The bucket you tried to delete is not empty.", StatusCode: http.StatusConflict}
	InvalidBucketName                  = APIError{Code: "InvalidBucketName", Message: "The specified bucket is not valid.", StatusCode: http.StatusBadRequest}
	EntityTooLarge                     = APIError{Code: "EntityTooLarge", Message: "Your proposed upload exceeds the maximum allowed object size.", StatusCode: http.StatusRequestEntityTooLarge}
	InvalidRange                       = APIError{Code: "InvalidRange", Message: "The requested range is not satisfiable.", StatusCode: http.StatusRequestedRangeNotSatisfiable}
	InvalidPart                        = APIError{Code: "InvalidPart", Message: "One or more of the specified parts could not be found.", StatusCode: http.StatusBadRequest}
	InvalidPartOrder                   = APIError{Code: "InvalidPartOrder", Message: "The list of parts was not in ascending order.", StatusCode: http.StatusBadRequest}
	BadDigest                          = APIError{Code: "BadDigest", Message: "The Content-MD5 you specified did not match what we received.", StatusCode: http.StatusBadRequest}
	InvalidRequest                     = APIError{Code: "InvalidRequest", Message: "The request is malformed or invalid for this operation.", StatusCode: http.StatusBadRequest}
	IllegalLocationConstraintException = APIError{
		Code:       "IllegalLocationConstraintException",
		Message:    "The specified location-constraint is not valid for this endpoint.",
		StatusCode: http.StatusBadRequest,
	}
	MethodNotAllowed = APIError{Code: "MethodNotAllowed", Message: "The specified method is not allowed against this resource.", StatusCode: http.StatusMethodNotAllowed}
	InternalError    = APIError{Code: "InternalError", Message: "We encountered an internal error. Please try again.", StatusCode: http.StatusInternalServerError}
)

type errorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId"`
}

func Write(w http.ResponseWriter, requestID string, apiErr APIError, resource string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(apiErr.StatusCode)
	_ = xml.NewEncoder(w).Encode(errorResponse{
		Code:      apiErr.Code,
		Message:   apiErr.Message,
		Resource:  resource,
		RequestID: requestID,
	})
}

func MapError(err error) APIError {
	var apiErr APIError
	var maxBytesErr *http.MaxBytesError
	switch {
	case err == nil:
		return InternalError
	case errors.As(err, &apiErr):
		return apiErr
	case errors.Is(err, storage.ErrNoSuchBucket):
		return NoSuchBucket
	case errors.Is(err, storage.ErrNoSuchBucketPolicy):
		return NoSuchBucketPolicy
	case errors.Is(err, storage.ErrNoSuchKey):
		return NoSuchKey
	case errors.Is(err, storage.ErrBucketNotEmpty):
		return BucketNotEmpty
	case errors.Is(err, storage.ErrBucketExists):
		return BucketAlreadyOwnedByYou
	case errors.Is(err, storage.ErrInvalidBucketName):
		return InvalidBucketName
	case errors.Is(err, storage.ErrEntityTooLarge):
		return EntityTooLarge
	case errors.As(err, &maxBytesErr):
		return EntityTooLarge
	case errors.Is(err, storage.ErrInvalidRange):
		return InvalidRange
	case errors.Is(err, storage.ErrNoSuchUpload):
		return NoSuchUpload
	case errors.Is(err, storage.ErrNoSuchVersion):
		return NoSuchVersion
	case errors.Is(err, storage.ErrNoSuchLifecycleConfiguration):
		return NoSuchLifecycleConfiguration
	case errors.Is(err, storage.ErrInvalidPart):
		return InvalidPart
	case errors.Is(err, storage.ErrInvalidPartOrder):
		return InvalidPartOrder
	case errors.Is(err, storage.ErrBadDigest):
		return BadDigest
	case errors.Is(err, storage.ErrInvalidRequest):
		return InvalidRequest
	case errors.Is(err, storage.ErrInvalidVersionID):
		return InvalidRequest
	case errors.Is(err, sigv4.ErrInvalidAccessKey):
		return InvalidAccessKeyID
	case errors.Is(err, sigv4.ErrClockSkew):
		return RequestTimeTooSkewed
	case errors.Is(err, sigv4.ErrInvalidPayloadHash), errors.Is(err, sigv4.ErrUnsupportedPayloadMode):
		return InvalidRequest
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return RequestTimeout
	case errors.Is(err, sigv4.ErrSignatureMismatch), errors.Is(err, sigv4.ErrInvalidCredentialScope), errors.Is(err, sigv4.ErrMalformedAuthorization), errors.Is(err, sigv4.ErrInvalidSignedHeaders), errors.Is(err, sigv4.ErrInvalidAmzDate):
		return SignatureDoesNotMatch
	case errors.Is(err, s3.ErrInvalidRequestPath):
		return InvalidBucketName
	case err.Error() == "invalid partNumber":
		return InvalidRequest
	default:
		return InternalError
	}
}
