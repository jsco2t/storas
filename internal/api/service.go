package api

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"storas/internal/authz"
	"storas/internal/policy"
	"storas/internal/s3"
	"storas/internal/s3err"
	"storas/internal/sigv4"
	"storas/internal/storage"
)

type Service struct {
	Backend           storage.Backend
	Authz             *authz.Engine
	Region            string
	ServiceName       string
	ClockSkew         time.Duration
	ServiceHost       string
	MaxBodyBytes      int64
	PathLive          string
	PathReady         string
	ReadyCheck        func() error
	Now               func() time.Time
	Logger            *slog.Logger
	TrustProxyHeaders bool
}

type requestContext struct {
	RequestID  string
	Principal  authz.Principal
	Auth       *sigv4.RequestAuth
	SigningKey []byte
	Target     s3.RequestTarget
	Operation  s3.Operation
	ErrorCode  string
	PolicyEval policy.EvaluationContext
}

func (s *Service) Handler() http.Handler {
	nowFn := s.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}

	serviceName := s.ServiceName
	if serviceName == "" {
		serviceName = "s3"
	}

	router := s3.NewRouter(s3.RouterConfig{
		ServiceHost: s.ServiceHost,
		PathLive:    s.PathLive,
		PathReady:   s.PathReady,
		ReadyCheck:  s.ReadyCheck,
		Handler: func(w http.ResponseWriter, r *http.Request, target s3.RequestTarget, op s3.Operation) {
			s.limitRequestBody(w, r, op)
			start := nowFn()
			reqID := s3.RequestIDFromContext(r.Context())
			ctx := requestContext{RequestID: reqID, Target: target, Operation: op}
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

			if op == s3.OperationUnknown {
				ctx.ErrorCode = s3err.MethodNotAllowed.Code
				s3err.Write(sw, reqID, s3err.MethodNotAllowed, r.URL.Path)
				s.logRequest(logger, r, sw.status, time.Since(start), ctx)
				return
			}

			principal, authReq, signingKey, err := s.authenticate(r, nowFn(), serviceName)
			if err != nil {
				apiErr := s3err.MapError(err)
				ctx.ErrorCode = apiErr.Code
				s3err.Write(sw, reqID, apiErr, resourceFromTarget(target))
				s.logRequest(logger, r, sw.status, time.Since(start), ctx)
				return
			}
			ctx.Principal = principal
			ctx.Auth = &authReq
			ctx.SigningKey = signingKey

			action, resource := mapAuthAction(op, target)
			policyEval := s.policyEvaluationContextFromRequest(r, op, principal)
			ctx.PolicyEval = policyEval
			allowed, err := s.isAuthorizedForOperation(r.Context(), principal, action, resource, op, policyEval)
			if err != nil {
				apiErr := s3err.MapError(err)
				ctx.ErrorCode = apiErr.Code
				s3err.Write(sw, reqID, apiErr, resourceFromTarget(target))
				s.logRequest(logger, r, sw.status, time.Since(start), ctx)
				return
			}
			if !allowed {
				ctx.ErrorCode = s3err.AccessDenied.Code
				s3err.Write(sw, reqID, s3err.AccessDenied, resource)
				s.logRequest(logger, r, sw.status, time.Since(start), ctx)
				return
			}

			rc := context.WithValue(r.Context(), ctxKey{}, ctx)
			if err := s.dispatch(sw, r.WithContext(rc), op, target); err != nil {
				apiErr := s3err.MapError(err)
				ctx.ErrorCode = apiErr.Code
				s3err.Write(sw, reqID, apiErr, resourceFromTarget(target))
			}
			s.logRequest(logger, r, sw.status, time.Since(start), ctx)
		},
	})

	return logHealthRequests(logger, router, s.PathLive, s.PathReady)
}

const (
	maxBucketPolicyBodyBytes = int64(20 * 1024)
)

func (s *Service) limitRequestBody(w http.ResponseWriter, r *http.Request, op s3.Operation) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	limit := s.MaxBodyBytes
	if op == s3.OperationPutBucketPolicy && (limit <= 0 || limit > maxBucketPolicyBodyBytes) {
		limit = maxBucketPolicyBodyBytes
	}
	if limit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
}

func (s *Service) logRequest(logger *slog.Logger, r *http.Request, status int, latency time.Duration, info requestContext) {
	principal := ""
	if info.Principal.AccessKey != "" {
		principal = info.Principal.AccessKey
	} else if info.Principal.Name != "" {
		principal = info.Principal.Name
	}
	logger.Info("request complete",
		"request_id", info.RequestID,
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.Path,
		"status_code", status,
		"latency_ms", latency.Milliseconds(),
		"principal", principal,
		"bucket", info.Target.Bucket,
		"key", info.Target.Key,
		"error_code", info.ErrorCode,
	)
}

func logHealthRequests(logger *slog.Logger, next http.Handler, pathLive, pathReady string) http.Handler {
	if pathLive == "" {
		pathLive = "/healthz"
	}
	if pathReady == "" {
		pathReady = "/readyz"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.URL.Path == pathLive || r.URL.Path == pathReady {
			logger.Info("request complete",
				"request_id", sw.Header().Get("X-Request-Id"),
				"remote_addr", r.RemoteAddr,
				"method", r.Method,
				"host", r.Host,
				"path", r.URL.Path,
				"status_code", sw.status,
				"latency_ms", time.Since(start).Milliseconds(),
				"principal", "",
				"bucket", "",
				"key", "",
				"error_code", "",
			)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	return s.ResponseWriter.Write(p)
}

func (s *Service) authenticate(r *http.Request, now time.Time, serviceName string) (authz.Principal, sigv4.RequestAuth, []byte, error) {
	authReq, err := sigv4.ParseRequestAuth(r, now, s.ClockSkew)
	if err != nil {
		return authz.Principal{}, sigv4.RequestAuth{}, nil, err
	}

	if err := sigv4.ValidateScope(authReq.Authorization.Credential, s.Region, serviceName); err != nil {
		return authz.Principal{}, sigv4.RequestAuth{}, nil, err
	}

	secret, principal, ok := s.Authz.SecretForAccessKey(authReq.Authorization.Credential.AccessKey)
	if !ok {
		return authz.Principal{}, sigv4.RequestAuth{}, nil, sigv4.ErrInvalidAccessKey
	}

	if err := sigv4.VerifyRequest(r, authReq, secret, s.Region, serviceName); err != nil {
		return authz.Principal{}, sigv4.RequestAuth{}, nil, err
	}

	signingKey := sigv4.SigningKey(secret, authReq.Authorization.Credential.Date, authReq.Authorization.Credential.Region, authReq.Authorization.Credential.Service)
	return principal, authReq, signingKey, nil
}

func mapAuthAction(op s3.Operation, target s3.RequestTarget) (string, string) {
	resource := resourceFromTarget(target)
	switch op {
	case s3.OperationListBuckets:
		return "bucket:list", "*"
	case s3.OperationCreateBucket:
		return "bucket:create", target.Bucket
	case s3.OperationDeleteBucket:
		return "bucket:delete", target.Bucket
	case s3.OperationHeadBucket:
		return "bucket:head", target.Bucket
	case s3.OperationGetBucketACL:
		return "bucket:head", target.Bucket
	case s3.OperationPutBucketACL:
		return "bucket:create", target.Bucket
	case s3.OperationGetBucketVersioning:
		return "bucket:head", target.Bucket
	case s3.OperationPutBucketVersioning:
		return "bucket:create", target.Bucket
	case s3.OperationGetBucketPolicy:
		return "bucket:head", target.Bucket
	case s3.OperationPutBucketPolicy:
		return "bucket:create", target.Bucket
	case s3.OperationDeleteBucketPolicy:
		return "bucket:delete", target.Bucket
	case s3.OperationGetBucketPolicyStatus:
		return "bucket:head", target.Bucket
	case s3.OperationGetBucketLifecycle:
		return "bucket:head", target.Bucket
	case s3.OperationPutBucketLifecycle:
		return "bucket:create", target.Bucket
	case s3.OperationDeleteBucketLifecycle:
		return "bucket:delete", target.Bucket
	case s3.OperationListObjects:
		return "object:list", target.Bucket + "/*"
	case s3.OperationListObjectVersions:
		return "object:list", target.Bucket + "/*"
	case s3.OperationPutObject:
		return "object:put", resource
	case s3.OperationPutObjectACL:
		return "object:put", resource
	case s3.OperationGetObject:
		return "object:get", resource
	case s3.OperationGetObjectACL:
		return "object:head", resource
	case s3.OperationHeadObject:
		return "object:head", resource
	case s3.OperationDeleteObject:
		return "object:delete", resource
	case s3.OperationCopyObject:
		return "object:copy", resource
	case s3.OperationCreateMultipartUpload, s3.OperationUploadPart, s3.OperationCompleteMultipartUpload, s3.OperationAbortMultipartUpload:
		return "object:put", resource
	case s3.OperationListMultipartUploads:
		return "object:list", target.Bucket + "/*"
	case s3.OperationListParts:
		return "object:head", resource
	default:
		return "", resource
	}
}

func resourceFromTarget(target s3.RequestTarget) string {
	if target.Bucket == "" {
		return "*"
	}
	if target.Key == "" {
		return target.Bucket
	}
	return target.Bucket + "/" + target.Key
}

type ctxKey struct{}

func (s *Service) dispatch(w http.ResponseWriter, r *http.Request, op s3.Operation, target s3.RequestTarget) error {
	if err := validateACLCompatibilityHeaders(r.Header, op); err != nil {
		return err
	}
	switch op {
	case s3.OperationListBuckets:
		return s.handleListBuckets(w, r)
	case s3.OperationCreateBucket:
		return s.handleCreateBucket(w, r, target.Bucket)
	case s3.OperationDeleteBucket:
		return s.handleDeleteBucket(w, r, target.Bucket)
	case s3.OperationHeadBucket:
		return s.handleHeadBucket(w, r, target.Bucket)
	case s3.OperationGetBucketACL:
		return s.handleGetBucketACL(w, r, target.Bucket)
	case s3.OperationPutBucketACL:
		return s.handlePutBucketACL(w, r, target.Bucket)
	case s3.OperationGetBucketVersioning:
		return s.handleGetBucketVersioning(w, r, target.Bucket)
	case s3.OperationPutBucketVersioning:
		return s.handlePutBucketVersioning(w, r, target.Bucket)
	case s3.OperationGetBucketPolicy:
		return s.handleGetBucketPolicy(w, r, target.Bucket)
	case s3.OperationPutBucketPolicy:
		return s.handlePutBucketPolicy(w, r, target.Bucket)
	case s3.OperationDeleteBucketPolicy:
		return s.handleDeleteBucketPolicy(w, r, target.Bucket)
	case s3.OperationGetBucketPolicyStatus:
		return s.handleGetBucketPolicyStatus(w, r, target.Bucket)
	case s3.OperationGetBucketLifecycle:
		return s.handleGetBucketLifecycle(w, r, target.Bucket)
	case s3.OperationPutBucketLifecycle:
		return s.handlePutBucketLifecycle(w, r, target.Bucket)
	case s3.OperationDeleteBucketLifecycle:
		return s.handleDeleteBucketLifecycle(w, r, target.Bucket)
	case s3.OperationListObjects:
		return s.handleListObjectsV2(w, r, target.Bucket)
	case s3.OperationListObjectVersions:
		return s.handleListObjectVersions(w, r, target.Bucket)
	case s3.OperationPutObject:
		return s.handlePutObject(w, r, target)
	case s3.OperationPutObjectACL:
		return s.handlePutObjectACL(w, r, target)
	case s3.OperationGetObject:
		return s.handleGetObject(w, r, target)
	case s3.OperationGetObjectACL:
		return s.handleGetObjectACL(w, r, target)
	case s3.OperationHeadObject:
		return s.handleHeadObject(w, r, target)
	case s3.OperationDeleteObject:
		return s.handleDeleteObject(w, r, target)
	case s3.OperationCopyObject:
		return s.handleCopyObject(w, r, target)
	case s3.OperationCreateMultipartUpload:
		return s.handleCreateMultipartUpload(w, r, target)
	case s3.OperationUploadPart:
		return s.handleUploadPart(w, r, target)
	case s3.OperationCompleteMultipartUpload:
		return s.handleCompleteMultipartUpload(w, r, target)
	case s3.OperationAbortMultipartUpload:
		return s.handleAbortMultipartUpload(w, r, target)
	case s3.OperationListMultipartUploads:
		return s.handleListMultipartUploads(w, r, target.Bucket)
	case s3.OperationListParts:
		return s.handleListParts(w, r, target)
	default:
		return fmt.Errorf("method not allowed")
	}
}

type listAllMyBucketsResult struct {
	XMLName xml.Name            `xml:"ListAllMyBucketsResult"`
	XMLNS   string              `xml:"xmlns,attr"`
	Owner   owner               `xml:"Owner"`
	Buckets []listBucketElement `xml:"Buckets>Bucket"`
}

type listBucketElement struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

func (s *Service) handleListBuckets(w http.ResponseWriter, r *http.Request) error {
	buckets, err := s.Backend.ListBuckets(r.Context())
	if err != nil {
		return err
	}
	result := listAllMyBucketsResult{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
		Owner: owner{ID: "local", DisplayName: "local"},
	}
	for _, bucket := range buckets {
		info, infoErr := s.Backend.GetBucketInfo(r.Context(), bucket)
		if infoErr != nil {
			return infoErr
		}
		result.Buckets = append(result.Buckets, listBucketElement{
			Name:         bucket,
			CreationDate: formatS3XMLTime(info.CreationDate),
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(result)
}

type createBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

func (s *Service) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) error {
	if r.Body != nil {
		decoder := xml.NewDecoder(r.Body)
		var cfg createBucketConfiguration
		if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
			if isRequestBodyTooLarge(err) {
				return storage.ErrEntityTooLarge
			}
			return storage.ErrInvalidRequest
		}
		location := strings.TrimSpace(cfg.LocationConstraint)
		if location != "" && location != s.Region {
			return s3err.IllegalLocationConstraintException
		}
		if cfg.XMLName.Local != "" && cfg.XMLName.Local != "CreateBucketConfiguration" {
			return storage.ErrInvalidRequest
		}
	}
	if err := s.Backend.CreateBucket(r.Context(), bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.DeleteBucket(r.Context(), bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.HeadBucket(r.Context(), bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

type aclAccessControlPolicy struct {
	XMLName           xml.Name        `xml:"AccessControlPolicy"`
	XMLNS             string          `xml:"xmlns,attr"`
	Owner             owner           `xml:"Owner"`
	AccessControlList aclGrantListXML `xml:"AccessControlList"`
}

type aclGrantListXML struct {
	Grants []aclGrantXML `xml:"Grant"`
}

type aclGrantXML struct {
	Grantee    aclGranteeXML `xml:"Grantee"`
	Permission string        `xml:"Permission"`
}

type aclGranteeXML struct {
	XMLNSXSI    string `xml:"xmlns:xsi,attr,omitempty"`
	XSIType     string `xml:"xsi:type,attr,omitempty"`
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

func (s *Service) handleGetBucketACL(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.HeadBucket(r.Context(), bucket); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(defaultACLPolicy())
}

func (s *Service) handlePutBucketACL(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.HeadBucket(r.Context(), bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

type bucketVersioningStatusConfig struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	XMLNS   string   `xml:"xmlns,attr,omitempty"`
	Status  string   `xml:"Status,omitempty"`
}

func (s *Service) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) error {
	status, err := s.Backend.GetBucketVersioning(r.Context(), bucket)
	if err != nil {
		return err
	}
	out := bucketVersioningStatusConfig{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
	}
	if status != storage.BucketVersioningOff {
		out.Status = string(status)
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(out)
}

func (s *Service) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.HeadBucket(r.Context(), bucket); err != nil {
		return err
	}
	var req bucketVersioningStatusConfig
	if r.Body != nil {
		dec := xml.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && err != io.EOF {
			if isRequestBodyTooLarge(err) {
				return storage.ErrEntityTooLarge
			}
			return storage.ErrInvalidRequest
		}
	}
	status := storage.BucketVersioningOff
	switch strings.TrimSpace(req.Status) {
	case "", string(storage.BucketVersioningOff):
		status = storage.BucketVersioningSuspended
	case string(storage.BucketVersioningEnabled):
		status = storage.BucketVersioningEnabled
	case string(storage.BucketVersioningSuspended):
		status = storage.BucketVersioningSuspended
	default:
		return storage.ErrInvalidRequest
	}
	if err := s.Backend.PutBucketVersioning(r.Context(), bucket, status); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

type bucketPolicyStatusResponse struct {
	XMLName  xml.Name `xml:"PolicyStatus"`
	XMLNS    string   `xml:"xmlns,attr,omitempty"`
	IsPublic bool     `xml:"IsPublic"`
}

func (s *Service) handleGetBucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) error {
	pol, err := s.Backend.GetBucketPolicy(r.Context(), bucket)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pol)
	return nil
}

func (s *Service) handlePutBucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) error {
	if r.Body == nil {
		return storage.ErrInvalidRequest
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isRequestBodyTooLarge(err) {
			return storage.ErrEntityTooLarge
		}
		return err
	}
	if _, err := policy.ParseAndValidate(body, bucket); err != nil {
		return err
	}
	if err := s.Backend.PutBucketPolicy(r.Context(), bucket, body); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteBucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.DeleteBucketPolicy(r.Context(), bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleGetBucketPolicyStatus(w http.ResponseWriter, r *http.Request, bucket string) error {
	pol, err := s.Backend.GetBucketPolicy(r.Context(), bucket)
	if err != nil {
		return err
	}
	doc, err := policy.ParseAndValidate(pol, bucket)
	if err != nil {
		return err
	}
	out := bucketPolicyStatusResponse{
		XMLNS:    "http://s3.amazonaws.com/doc/2006-03-01/",
		IsPublic: policy.IsPublic(doc),
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(out)
}

type lifecycleConfigurationXML struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

type lifecycleRuleXML struct {
	ID         string             `xml:"ID,omitempty"`
	Status     string             `xml:"Status"`
	Prefix     string             `xml:"Prefix,omitempty"`
	Filter     lifecycleFilterXML `xml:"Filter"`
	Expiration struct {
		Days int    `xml:"Days,omitempty"`
		Date string `xml:"Date,omitempty"`
	} `xml:"Expiration"`
	NoncurrentVersionExpiration struct {
		NoncurrentDays int `xml:"NoncurrentDays,omitempty"`
	} `xml:"NoncurrentVersionExpiration"`
	AbortIncompleteMultipartUpload struct {
		DaysAfterInitiation int `xml:"DaysAfterInitiation,omitempty"`
	} `xml:"AbortIncompleteMultipartUpload"`
}

type lifecycleTagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type lifecycleAndXML struct {
	Prefix                string            `xml:"Prefix,omitempty"`
	Tags                  []lifecycleTagXML `xml:"Tag,omitempty"`
	ObjectSizeGreaterThan int64             `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    int64             `xml:"ObjectSizeLessThan,omitempty"`
}

type lifecycleFilterXML struct {
	Prefix                string           `xml:"Prefix,omitempty"`
	Tag                   *lifecycleTagXML `xml:"Tag,omitempty"`
	And                   *lifecycleAndXML `xml:"And,omitempty"`
	ObjectSizeGreaterThan int64            `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    int64            `xml:"ObjectSizeLessThan,omitempty"`
}

func (s *Service) handleGetBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) error {
	cfg, err := s.Backend.GetBucketLifecycle(r.Context(), bucket)
	if err != nil {
		return err
	}
	out := lifecycleConfigurationXML{}
	for _, rule := range cfg.Rules {
		item := lifecycleRuleXML{ID: rule.ID, Status: rule.Status}
		switch {
		case len(rule.Tags) == 0 && rule.ObjectSizeGreaterThan == 0 && rule.ObjectSizeLessThan == 0:
			item.Filter.Prefix = rule.Prefix
		case len(rule.Tags) == 1 && strings.TrimSpace(rule.Prefix) == "" && rule.ObjectSizeGreaterThan == 0 && rule.ObjectSizeLessThan == 0:
			tags := sortedLifecycleTags(rule.Tags)
			item.Filter.Tag = &tags[0]
		default:
			item.Filter.And = &lifecycleAndXML{
				Prefix:                rule.Prefix,
				Tags:                  sortedLifecycleTags(rule.Tags),
				ObjectSizeGreaterThan: rule.ObjectSizeGreaterThan,
				ObjectSizeLessThan:    rule.ObjectSizeLessThan,
			}
		}
		if rule.ExpirationDays > 0 {
			item.Expiration.Days = rule.ExpirationDays
		}
		if !rule.ExpirationDate.IsZero() {
			item.Expiration.Date = rule.ExpirationDate.UTC().Format(time.RFC3339)
		}
		if rule.NoncurrentExpirationDays > 0 {
			item.NoncurrentVersionExpiration.NoncurrentDays = rule.NoncurrentExpirationDays
		}
		if rule.AbortIncompleteUploadDays > 0 {
			item.AbortIncompleteMultipartUpload.DaysAfterInitiation = rule.AbortIncompleteUploadDays
		}
		out.Rules = append(out.Rules, item)
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(out)
}

func (s *Service) handlePutBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.HeadBucket(r.Context(), bucket); err != nil {
		return err
	}
	var req lifecycleConfigurationXML
	if r.Body == nil {
		return storage.ErrInvalidRequest
	}
	dec := xml.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		if isRequestBodyTooLarge(err) {
			return storage.ErrEntityTooLarge
		}
		return storage.ErrInvalidRequest
	}
	cfg, err := validateLifecycleConfiguration(req)
	if err != nil {
		return err
	}
	if err := s.Backend.PutBucketLifecycle(r.Context(), bucket, cfg); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) error {
	if err := s.Backend.DeleteBucketLifecycle(r.Context(), bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func validateLifecycleConfiguration(in lifecycleConfigurationXML) (storage.LifecycleConfiguration, error) {
	if len(in.Rules) == 0 {
		return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
	}
	cfg := storage.LifecycleConfiguration{Rules: make([]storage.LifecycleRule, 0, len(in.Rules))}
	for _, rule := range in.Rules {
		status := strings.TrimSpace(rule.Status)
		if status != "Enabled" && status != "Disabled" {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}
		filterPrefix := strings.TrimSpace(rule.Filter.Prefix)
		legacyPrefix := strings.TrimSpace(rule.Prefix)
		filterTag := rule.Filter.Tag
		filterAnd := rule.Filter.And
		filterSizeGreaterThan := rule.Filter.ObjectSizeGreaterThan
		filterSizeLessThan := rule.Filter.ObjectSizeLessThan
		filterUsed := filterPrefix != "" || filterTag != nil || filterAnd != nil || filterSizeGreaterThan > 0 || filterSizeLessThan > 0
		if filterUsed && legacyPrefix != "" {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}
		prefix := ""
		tags := map[string]string{}
		objectSizeGreaterThan := int64(0)
		objectSizeLessThan := int64(0)
		switch {
		case filterAnd != nil:
			if filterPrefix != "" || filterTag != nil || filterSizeGreaterThan > 0 || filterSizeLessThan > 0 {
				return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
			}
			prefix = strings.TrimSpace(filterAnd.Prefix)
			parsedTags, err := parseLifecycleTags(filterAnd.Tags)
			if err != nil {
				return storage.LifecycleConfiguration{}, err
			}
			tags = parsedTags
			objectSizeGreaterThan = filterAnd.ObjectSizeGreaterThan
			objectSizeLessThan = filterAnd.ObjectSizeLessThan
			if prefix == "" && len(tags) == 0 {
				if objectSizeGreaterThan == 0 && objectSizeLessThan == 0 {
					return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
				}
			}
		case filterTag != nil:
			if filterPrefix != "" || filterSizeGreaterThan > 0 || filterSizeLessThan > 0 {
				return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
			}
			parsedTag, err := parseLifecycleTag(*filterTag)
			if err != nil {
				return storage.LifecycleConfiguration{}, err
			}
			tags[parsedTag.Key] = parsedTag.Value
		case filterPrefix != "":
			prefix = filterPrefix
		default:
			prefix = legacyPrefix
			objectSizeGreaterThan = filterSizeGreaterThan
			objectSizeLessThan = filterSizeLessThan
		}
		if filterPrefix != "" || legacyPrefix != "" || filterTag != nil || filterAnd != nil {
			if filterAnd == nil {
				objectSizeGreaterThan = filterSizeGreaterThan
				objectSizeLessThan = filterSizeLessThan
			}
		}
		if len(tags) == 0 {
			tags = nil
		}
		if objectSizeGreaterThan < 0 || objectSizeLessThan < 0 {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}
		if objectSizeGreaterThan > 0 && objectSizeLessThan > 0 && objectSizeGreaterThan >= objectSizeLessThan {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}

		expDays := rule.Expiration.Days
		expirationDate, err := parseLifecycleExpirationDate(rule.Expiration.Date)
		if err != nil {
			return storage.LifecycleConfiguration{}, err
		}
		noncurrentDays := rule.NoncurrentVersionExpiration.NoncurrentDays
		abortDays := rule.AbortIncompleteMultipartUpload.DaysAfterInitiation
		if expDays < 0 || noncurrentDays < 0 || abortDays < 0 {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}
		if expDays > 0 && !expirationDate.IsZero() {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}
		if expDays == 0 && expirationDate.IsZero() && noncurrentDays == 0 && abortDays == 0 {
			return storage.LifecycleConfiguration{}, storage.ErrInvalidRequest
		}
		cfg.Rules = append(cfg.Rules, storage.LifecycleRule{
			ID:                        strings.TrimSpace(rule.ID),
			Status:                    status,
			Prefix:                    prefix,
			Tags:                      tags,
			ObjectSizeGreaterThan:     objectSizeGreaterThan,
			ObjectSizeLessThan:        objectSizeLessThan,
			ExpirationDays:            expDays,
			ExpirationDate:            expirationDate,
			NoncurrentExpirationDays:  noncurrentDays,
			AbortIncompleteUploadDays: abortDays,
		})
	}
	return cfg, nil
}

func parseLifecycleExpirationDate(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	layouts := []string{time.RFC3339, "2006-01-02"}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, storage.ErrInvalidRequest
}

func parseLifecycleTag(tag lifecycleTagXML) (lifecycleTagXML, error) {
	key := strings.TrimSpace(tag.Key)
	if key == "" {
		return lifecycleTagXML{}, storage.ErrInvalidRequest
	}
	return lifecycleTagXML{Key: key, Value: tag.Value}, nil
}

func parseLifecycleTags(tags []lifecycleTagXML) (map[string]string, error) {
	if len(tags) == 0 {
		return map[string]string{}, nil
	}
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		parsed, err := parseLifecycleTag(tag)
		if err != nil {
			return nil, err
		}
		if _, exists := out[parsed.Key]; exists {
			return nil, storage.ErrInvalidRequest
		}
		out[parsed.Key] = parsed.Value
	}
	return out, nil
}

func sortedLifecycleTags(tags map[string]string) []lifecycleTagXML {
	if len(tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]lifecycleTagXML, 0, len(keys))
	for _, key := range keys {
		out = append(out, lifecycleTagXML{Key: key, Value: tags[key]})
	}
	return out
}

type listBucketResult struct {
	XMLName               xml.Name             `xml:"ListBucketResult"`
	XMLNS                 string               `xml:"xmlns,attr"`
	Name                  string               `xml:"Name"`
	EncodingType          string               `xml:"EncodingType,omitempty"`
	Prefix                string               `xml:"Prefix,omitempty"`
	Delimiter             string               `xml:"Delimiter,omitempty"`
	StartAfter            string               `xml:"StartAfter,omitempty"`
	ContinuationToken     string               `xml:"ContinuationToken,omitempty"`
	KeyCount              int                  `xml:"KeyCount"`
	MaxKeys               int                  `xml:"MaxKeys"`
	IsTruncated           bool                 `xml:"IsTruncated"`
	NextContinuationToken string               `xml:"NextContinuationToken,omitempty"`
	Contents              []listObjectContents `xml:"Contents"`
	CommonPrefixes        []commonPrefix       `xml:"CommonPrefixes"`
}

type listObjectContents struct {
	Key          string `xml:"Key"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	LastModified string `xml:"LastModified"`
	Owner        *owner `xml:"Owner,omitempty"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

func (s *Service) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) error {
	q := r.URL.Query()
	listType, err := getSingleQueryValue(q, "list-type")
	if err != nil {
		return err
	}
	if listType != "" && listType != "2" {
		return storage.ErrInvalidRequest
	}
	encodingType, err := getSingleQueryValue(q, "encoding-type")
	if err != nil {
		return err
	}
	if encodingType != "" && encodingType != "url" {
		return storage.ErrInvalidRequest
	}
	fetchOwnerValue, err := getSingleQueryValue(q, "fetch-owner")
	if err != nil {
		return err
	}
	fetchOwner := false
	if fetchOwnerValue != "" {
		parsed, parseErr := strconv.ParseBool(fetchOwnerValue)
		if parseErr != nil {
			return storage.ErrInvalidRequest
		}
		fetchOwner = parsed
	}
	maxKeys := 1000
	maxKeysValue, err := getSingleQueryValue(q, "max-keys")
	if err != nil {
		return err
	}
	if maxKeysValue != "" {
		parsed, parseErr := strconv.Atoi(maxKeysValue)
		if parseErr != nil || parsed < 0 {
			return storage.ErrInvalidRequest
		}
		maxKeys = parsed
	}
	if maxKeys > 1000 {
		maxKeys = 1000
	}
	prefix, err := getSingleQueryValue(q, "prefix")
	if err != nil {
		return err
	}
	delimiter, err := getSingleQueryValue(q, "delimiter")
	if err != nil {
		return err
	}
	continuationTokenValue, err := getSingleQueryValue(q, "continuation-token")
	if err != nil {
		return err
	}
	startAfter, err := getSingleQueryValue(q, "start-after")
	if err != nil {
		return err
	}

	res, err := s.Backend.ListObjectsV2(r.Context(), bucket, storage.ListObjectsOptions{
		Prefix:            prefix,
		Delimiter:         delimiter,
		ContinuationToken: continuationTokenValue,
		StartAfter:        startAfter,
		MaxKeys:           maxKeys,
	})
	if err != nil {
		return err
	}

	continuationToken := continuationTokenValue
	nextContinuationToken := res.NextContinuationToken
	if encodingType == "url" {
		prefix = url.PathEscape(prefix)
		delimiter = url.PathEscape(delimiter)
		startAfter = url.PathEscape(startAfter)
		continuationToken = url.PathEscape(continuationToken)
		nextContinuationToken = url.PathEscape(nextContinuationToken)
	}

	result := listBucketResult{
		XMLNS:                 "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:                  bucket,
		EncodingType:          encodingType,
		Prefix:                prefix,
		Delimiter:             delimiter,
		StartAfter:            startAfter,
		ContinuationToken:     continuationToken,
		KeyCount:              len(res.Objects) + len(res.CommonPrefixes),
		MaxKeys:               maxKeys,
		IsTruncated:           res.IsTruncated,
		NextContinuationToken: nextContinuationToken,
	}
	for _, obj := range res.Objects {
		key := obj.Key
		if encodingType == "url" {
			key = url.PathEscape(key)
		}
		item := listObjectContents{Key: key, ETag: quoteETag(obj.ETag), Size: obj.Size, LastModified: formatS3XMLTime(obj.Modified)}
		if fetchOwner {
			item.Owner = &owner{ID: "local", DisplayName: "local"}
		}
		result.Contents = append(result.Contents, item)
	}
	for _, prefix := range res.CommonPrefixes {
		p := prefix
		if encodingType == "url" {
			p = url.PathEscape(prefix)
		}
		result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix{Prefix: p})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(result)
}

func (s *Service) handlePutObject(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	meta := storage.ObjectMetadata{
		ContentType:  r.Header.Get("Content-Type"),
		UserMetadata: map[string]string{},
	}
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-meta-") && len(values) > 0 {
			meta.UserMetadata[strings.TrimPrefix(lower, "x-amz-meta-")] = values[0]
		}
	}
	if err := validateUserMetadata(meta.UserMetadata); err != nil {
		return err
	}
	var err error
	meta.ObjectTags, err = parseObjectTaggingHeader(r.Header.Get("x-amz-tagging"))
	if err != nil {
		return err
	}
	body, cleanup, err := bodyReaderForContentMD5(r, r.Body)
	if err != nil {
		return err
	}
	defer cleanup()

	obj, err := s.Backend.PutObject(r.Context(), target.Bucket, target.Key, body, meta)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", quoteETag(obj.ETag))
	if obj.VersionID != "" {
		w.Header().Set("x-amz-version-id", obj.VersionID)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleGetObject(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	versionID, err := getSingleQueryValue(r.URL.Query(), "versionId")
	if err != nil {
		return err
	}
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		if ifRange := r.Header.Get("If-Range"); ifRange != "" {
			meta, err := s.Backend.HeadObjectVersion(r.Context(), target.Bucket, target.Key, versionID)
			if err != nil {
				return err
			}
			if !ifRangeMatches(meta, ifRange) {
				rangeHeader = ""
			}
		}
	}
	if rangeHeader != "" {
		rc, meta, start, end, err := s.Backend.GetObjectRangeVersion(r.Context(), target.Bucket, target.Key, versionID, rangeHeader)
		if err != nil {
			return err
		}
		defer rc.Close()
		if handled := applyConditionalHeaders(w, r, meta); handled {
			return nil
		}
		applyMetadataHeaders(w.Header(), meta)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, meta.ContentLength))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.Copy(w, rc)
		return nil
	}

	rc, meta, err := s.Backend.GetObjectVersion(r.Context(), target.Bucket, target.Key, versionID)
	if err != nil {
		return err
	}
	defer rc.Close()
	if handled := applyConditionalHeaders(w, r, meta); handled {
		return nil
	}
	applyMetadataHeaders(w.Header(), meta)
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
	return nil
}

func (s *Service) handleHeadObject(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	versionID, err := getSingleQueryValue(r.URL.Query(), "versionId")
	if err != nil {
		return err
	}
	meta, err := s.Backend.HeadObjectVersion(r.Context(), target.Bucket, target.Key, versionID)
	if err != nil {
		return err
	}
	if handled := applyConditionalHeaders(w, r, meta); handled {
		return nil
	}
	applyMetadataHeaders(w.Header(), meta)
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleGetObjectACL(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	if _, err := s.Backend.HeadObject(r.Context(), target.Bucket, target.Key); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(defaultACLPolicy())
}

func (s *Service) handlePutObjectACL(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	if _, err := s.Backend.HeadObject(r.Context(), target.Bucket, target.Key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleDeleteObject(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	versionID, err := getSingleQueryValue(r.URL.Query(), "versionId")
	if err != nil {
		return err
	}
	result, err := s.Backend.DeleteObjectVersion(r.Context(), target.Bucket, target.Key, versionID)
	if err != nil {
		return err
	}
	if result.VersionID != "" {
		w.Header().Set("x-amz-version-id", result.VersionID)
	}
	if result.DeleteMarker {
		w.Header().Set("x-amz-delete-marker", "true")
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type listObjectVersionsResult struct {
	XMLName             xml.Name               `xml:"ListVersionsResult"`
	XMLNS               string                 `xml:"xmlns,attr"`
	Name                string                 `xml:"Name"`
	Prefix              string                 `xml:"Prefix,omitempty"`
	KeyMarker           string                 `xml:"KeyMarker,omitempty"`
	VersionIDMarker     string                 `xml:"VersionIdMarker,omitempty"`
	NextKeyMarker       string                 `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string                 `xml:"NextVersionIdMarker,omitempty"`
	MaxKeys             int                    `xml:"MaxKeys"`
	IsTruncated         bool                   `xml:"IsTruncated"`
	Version             []listObjectVersionXML `xml:"Version"`
	DeleteMarker        []deleteMarkerXML      `xml:"DeleteMarker"`
}

type listObjectVersionXML struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	Owner        owner  `xml:"Owner"`
}

type deleteMarkerXML struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	Owner        owner  `xml:"Owner"`
}

func (s *Service) handleListObjectVersions(w http.ResponseWriter, r *http.Request, bucket string) error {
	q := r.URL.Query()
	prefix, err := getSingleQueryValue(q, "prefix")
	if err != nil {
		return err
	}
	keyMarker, err := getSingleQueryValue(q, "key-marker")
	if err != nil {
		return err
	}
	versionIDMarker, err := getSingleQueryValue(q, "version-id-marker")
	if err != nil {
		return err
	}
	maxKeys := 1000
	maxKeysValue, err := getSingleQueryValue(q, "max-keys")
	if err != nil {
		return err
	}
	if maxKeysValue != "" {
		parsed, parseErr := strconv.Atoi(maxKeysValue)
		if parseErr != nil || parsed < 0 {
			return storage.ErrInvalidRequest
		}
		maxKeys = parsed
	}
	if maxKeys > 1000 {
		maxKeys = 1000
	}

	result, err := s.Backend.ListObjectVersions(r.Context(), bucket, storage.ListObjectVersionsOptions{
		Prefix:          prefix,
		KeyMarker:       keyMarker,
		VersionIDMarker: versionIDMarker,
		MaxKeys:         maxKeys,
	})
	if err != nil {
		return err
	}
	out := listObjectVersionsResult{
		XMLNS:               "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:                bucket,
		Prefix:              prefix,
		KeyMarker:           keyMarker,
		VersionIDMarker:     versionIDMarker,
		NextKeyMarker:       result.NextKeyMarker,
		NextVersionIDMarker: result.NextVersionIDMarker,
		MaxKeys:             maxKeys,
		IsTruncated:         result.IsTruncated,
	}
	for _, v := range result.Versions {
		if v.IsDeleteMark {
			out.DeleteMarker = append(out.DeleteMarker, deleteMarkerXML{
				Key:          v.Key,
				VersionID:    v.VersionID,
				IsLatest:     v.IsLatest,
				LastModified: formatS3XMLTime(v.LastModified),
				Owner:        owner{ID: "local", DisplayName: "local"},
			})
			continue
		}
		out.Version = append(out.Version, listObjectVersionXML{
			Key:          v.Key,
			VersionID:    v.VersionID,
			IsLatest:     v.IsLatest,
			LastModified: formatS3XMLTime(v.LastModified),
			ETag:         quoteETag(v.ETag),
			Size:         v.Size,
			StorageClass: "STANDARD",
			Owner:        owner{ID: "local", DisplayName: "local"},
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(out)
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

func (s *Service) handleCopyObject(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	if hasCopySourceConditionalHeader(r.Header) {
		return storage.ErrInvalidRequest
	}
	headerSource := r.Header.Get("X-Amz-Copy-Source")
	querySource, err := getSingleQueryValue(r.URL.Query(), "x-amz-copy-source")
	if err != nil {
		return err
	}
	rawSource := headerSource
	if rawSource == "" {
		rawSource = querySource
	}
	if headerSource != "" && querySource != "" && headerSource != querySource {
		return storage.ErrInvalidRequest
	}
	if rawSource == "" {
		return storage.ErrInvalidRequest
	}
	srcBucket, srcKey, err := parseCopySource(rawSource)
	if err != nil {
		return err
	}
	if !s.isAllowedFromContext(r.Context(), "object:get", srcBucket+"/"+srcKey) {
		return s3err.AccessDenied
	}

	var obj storage.ObjectInfo
	if strings.EqualFold(r.Header.Get("x-amz-metadata-directive"), "REPLACE") {
		rc, _, getErr := s.Backend.GetObject(r.Context(), srcBucket, srcKey)
		if getErr != nil {
			return getErr
		}
		defer rc.Close()
		meta := storage.ObjectMetadata{ContentType: r.Header.Get("Content-Type"), UserMetadata: map[string]string{}}
		for key, values := range r.Header {
			lower := strings.ToLower(key)
			if strings.HasPrefix(lower, "x-amz-meta-") && len(values) > 0 {
				meta.UserMetadata[strings.TrimPrefix(lower, "x-amz-meta-")] = values[0]
			}
		}
		if err := validateUserMetadata(meta.UserMetadata); err != nil {
			return err
		}
		meta.ObjectTags, err = parseObjectTaggingHeader(r.Header.Get("x-amz-tagging"))
		if err != nil {
			return err
		}
		obj, err = s.Backend.PutObject(r.Context(), target.Bucket, target.Key, rc, meta)
		if err != nil {
			return err
		}
	} else {
		obj, err = s.Backend.CopyObject(r.Context(), srcBucket, srcKey, target.Bucket, target.Key)
		if err != nil {
			return err
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	if obj.VersionID != "" {
		w.Header().Set("x-amz-version-id", obj.VersionID)
	}
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(copyObjectResult{ETag: quoteETag(obj.ETag), LastModified: formatS3XMLTime(obj.Modified)})
}

type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

func (s *Service) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	meta := storage.ObjectMetadata{
		ContentType:  r.Header.Get("Content-Type"),
		UserMetadata: map[string]string{},
	}
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-meta-") && len(values) > 0 {
			meta.UserMetadata[strings.TrimPrefix(lower, "x-amz-meta-")] = values[0]
		}
	}
	if err := validateUserMetadata(meta.UserMetadata); err != nil {
		return err
	}
	var err error
	meta.ObjectTags, err = parseObjectTaggingHeader(r.Header.Get("x-amz-tagging"))
	if err != nil {
		return err
	}
	uploadID, err := s.Backend.CreateMultipartUpload(r.Context(), target.Bucket, target.Key, meta)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(initiateMultipartUploadResult{
		XMLNS:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:   target.Bucket,
		Key:      target.Key,
		UploadID: uploadID,
	})
}

func (s *Service) handleUploadPart(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	q := r.URL.Query()
	uploadID, err := getSingleQueryValue(q, "uploadId")
	if err != nil {
		return err
	}
	if uploadID == "" {
		return storage.ErrInvalidRequest
	}
	partNumberValue, err := getSingleQueryValue(q, "partNumber")
	if err != nil {
		return err
	}
	partNumber, err := strconv.Atoi(partNumberValue)
	if err != nil || partNumber <= 0 {
		return storage.ErrInvalidRequest
	}
	body, cleanup, err := bodyReaderForContentMD5(r, r.Body)
	if err != nil {
		return err
	}
	defer cleanup()
	part, err := s.Backend.UploadPart(r.Context(), target.Bucket, target.Key, uploadID, partNumber, body)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", quoteETag(part.ETag))
	w.WriteHeader(http.StatusOK)
	return nil
}

type completeMultipartUploadRequest struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

func (s *Service) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	q := r.URL.Query()
	uploadID, err := getSingleQueryValue(q, "uploadId")
	if err != nil {
		return err
	}
	if uploadID == "" {
		return storage.ErrInvalidRequest
	}
	var reqBody completeMultipartUploadRequest
	if r.Body != nil {
		decoder := xml.NewDecoder(r.Body)
		if err := decoder.Decode(&reqBody); err != nil && err != io.EOF {
			if isRequestBodyTooLarge(err) {
				return storage.ErrEntityTooLarge
			}
			return storage.ErrInvalidPart
		}
		if reqBody.XMLName.Local != "" && reqBody.XMLName.Local != "CompleteMultipartUpload" {
			return storage.ErrInvalidPart
		}
	}

	parts := make([]storage.CompletedPart, 0, len(reqBody.Parts))
	for _, part := range reqBody.Parts {
		if part.PartNumber <= 0 {
			return storage.ErrInvalidRequest
		}
		parts = append(parts, storage.CompletedPart{PartNumber: part.PartNumber, ETag: part.ETag})
	}

	obj, err := s.Backend.CompleteMultipartUpload(r.Context(), target.Bucket, target.Key, uploadID, parts)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/xml")
	if obj.VersionID != "" {
		w.Header().Set("x-amz-version-id", obj.VersionID)
	}
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(completeMultipartUploadResult{
		XMLNS:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Location: "/" + target.Bucket + "/" + target.Key,
		Bucket:   target.Bucket,
		Key:      target.Key,
		ETag:     quoteETag(obj.ETag),
	})
}

func (s *Service) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	uploadID, err := getSingleQueryValue(r.URL.Query(), "uploadId")
	if err != nil {
		return err
	}
	if uploadID == "" {
		return storage.ErrInvalidRequest
	}
	if err := s.Backend.AbortMultipartUpload(r.Context(), target.Bucket, target.Key, uploadID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type listMultipartUploadsResult struct {
	XMLName            xml.Name                 `xml:"ListMultipartUploadsResult"`
	XMLNS              string                   `xml:"xmlns,attr"`
	Bucket             string                   `xml:"Bucket"`
	EncodingType       string                   `xml:"EncodingType,omitempty"`
	Prefix             string                   `xml:"Prefix,omitempty"`
	KeyMarker          string                   `xml:"KeyMarker,omitempty"`
	UploadIDMarker     string                   `xml:"UploadIdMarker,omitempty"`
	NextKeyMarker      string                   `xml:"NextKeyMarker,omitempty"`
	NextUploadIDMarker string                   `xml:"NextUploadIdMarker,omitempty"`
	MaxUploads         int                      `xml:"MaxUploads"`
	IsTruncated        bool                     `xml:"IsTruncated"`
	Uploads            []listMultipartUploadXML `xml:"Upload"`
}

type listMultipartUploadXML struct {
	Key       string `xml:"Key"`
	UploadID  string `xml:"UploadId"`
	Initiated string `xml:"Initiated"`
}

func (s *Service) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) error {
	q := r.URL.Query()
	uploadIDMarker, err := getSingleQueryValue(q, "upload-id-marker")
	if err != nil {
		return err
	}
	keyMarker, err := getSingleQueryValue(q, "key-marker")
	if err != nil {
		return err
	}
	if uploadIDMarker != "" && keyMarker == "" {
		return storage.ErrInvalidRequest
	}
	encodingType, err := getSingleQueryValue(q, "encoding-type")
	if err != nil {
		return err
	}
	if encodingType != "" && encodingType != "url" {
		return storage.ErrInvalidRequest
	}
	prefix, err := getSingleQueryValue(q, "prefix")
	if err != nil {
		return err
	}
	maxUploads := 1000
	maxUploadsValue, err := getSingleQueryValue(q, "max-uploads")
	if err != nil {
		return err
	}
	if maxUploadsValue != "" {
		parsed, parseErr := strconv.Atoi(maxUploadsValue)
		if parseErr != nil || parsed <= 0 {
			return storage.ErrInvalidRequest
		}
		maxUploads = parsed
	}
	if maxUploads > 1000 {
		maxUploads = 1000
	}

	res, err := s.Backend.ListMultipartUploads(r.Context(), bucket, storage.MultipartUploadListOptions{
		Prefix:            prefix,
		KeyMarker:         keyMarker,
		UploadIDMarker:    uploadIDMarker,
		HasUploadIDMarker: uploadIDMarker != "",
		MaxUploads:        maxUploads,
	})
	if err != nil {
		return err
	}

	nextKeyMarker := res.NextKeyMarker
	nextUploadIDMarker := res.NextUploadIDMarker
	if encodingType == "url" {
		prefix = url.PathEscape(prefix)
		keyMarker = url.PathEscape(keyMarker)
		uploadIDMarker = url.PathEscape(uploadIDMarker)
		nextKeyMarker = url.PathEscape(nextKeyMarker)
		nextUploadIDMarker = url.PathEscape(nextUploadIDMarker)
	}

	out := listMultipartUploadsResult{
		XMLNS:              "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:             bucket,
		EncodingType:       encodingType,
		Prefix:             prefix,
		KeyMarker:          keyMarker,
		UploadIDMarker:     uploadIDMarker,
		NextKeyMarker:      nextKeyMarker,
		NextUploadIDMarker: nextUploadIDMarker,
		MaxUploads:         maxUploads,
		IsTruncated:        res.IsTruncated,
	}
	for _, upload := range res.Uploads {
		key := upload.Key
		uploadID := upload.UploadID
		if encodingType == "url" {
			key = url.PathEscape(key)
			uploadID = url.PathEscape(uploadID)
		}
		out.Uploads = append(out.Uploads, listMultipartUploadXML{
			Key:       key,
			UploadID:  uploadID,
			Initiated: formatS3XMLTime(upload.Initiated),
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(out)
}

type listPartsResult struct {
	XMLName              xml.Name         `xml:"ListPartsResult"`
	XMLNS                string           `xml:"xmlns,attr"`
	Bucket               string           `xml:"Bucket"`
	EncodingType         string           `xml:"EncodingType,omitempty"`
	Key                  string           `xml:"Key"`
	UploadID             string           `xml:"UploadId"`
	PartNumberMarker     int              `xml:"PartNumberMarker"`
	NextPartNumberMarker int              `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int              `xml:"MaxParts"`
	IsTruncated          bool             `xml:"IsTruncated"`
	Parts                []listPartResult `xml:"Part"`
}

func defaultACLPolicy() aclAccessControlPolicy {
	return aclAccessControlPolicy{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
		Owner: owner{ID: "local", DisplayName: "local"},
		AccessControlList: aclGrantListXML{
			Grants: []aclGrantXML{
				{
					Grantee: aclGranteeXML{
						XMLNSXSI:    "http://www.w3.org/2001/XMLSchema-instance",
						XSIType:     "CanonicalUser",
						ID:          "local",
						DisplayName: "local",
					},
					Permission: "FULL_CONTROL",
				},
			},
		},
	}
}

type listPartResult struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

func (s *Service) handleListParts(w http.ResponseWriter, r *http.Request, target s3.RequestTarget) error {
	q := r.URL.Query()
	uploadID, err := getSingleQueryValue(q, "uploadId")
	if err != nil {
		return err
	}
	if uploadID == "" {
		return storage.ErrInvalidRequest
	}
	encodingType, err := getSingleQueryValue(q, "encoding-type")
	if err != nil {
		return err
	}
	if encodingType != "" && encodingType != "url" {
		return storage.ErrInvalidRequest
	}
	partNumberMarker := 0
	partNumberMarkerValue, err := getSingleQueryValue(q, "part-number-marker")
	if err != nil {
		return err
	}
	if partNumberMarkerValue != "" {
		parsed, parseErr := strconv.Atoi(partNumberMarkerValue)
		if parseErr != nil || parsed < 0 || parsed > 10000 {
			return storage.ErrInvalidRequest
		}
		partNumberMarker = parsed
	}
	maxParts := 1000
	maxPartsValue, err := getSingleQueryValue(q, "max-parts")
	if err != nil {
		return err
	}
	if maxPartsValue != "" {
		parsed, parseErr := strconv.Atoi(maxPartsValue)
		if parseErr != nil || parsed <= 0 {
			return storage.ErrInvalidRequest
		}
		maxParts = parsed
	}
	if maxParts > 1000 {
		maxParts = 1000
	}

	res, err := s.Backend.ListParts(r.Context(), target.Bucket, target.Key, uploadID, storage.ListPartsOptions{
		PartNumberMarker: partNumberMarker,
		MaxParts:         maxParts,
	})
	if err != nil {
		return err
	}

	key := target.Key
	uploadIDOut := uploadID
	if encodingType == "url" {
		key = url.PathEscape(key)
		uploadIDOut = url.PathEscape(uploadID)
	}

	out := listPartsResult{
		XMLNS:                "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:               target.Bucket,
		EncodingType:         encodingType,
		Key:                  key,
		UploadID:             uploadIDOut,
		PartNumberMarker:     partNumberMarker,
		NextPartNumberMarker: res.NextPartNumberMarker,
		MaxParts:             maxParts,
		IsTruncated:          res.IsTruncated,
	}
	for _, part := range res.Parts {
		out.Parts = append(out.Parts, listPartResult{
			PartNumber:   part.PartNumber,
			LastModified: formatS3XMLTime(part.LastModified),
			ETag:         quoteETag(part.ETag),
			Size:         part.Size,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(out)
}

func parseCopySource(value string) (string, string, error) {
	trimmed := strings.TrimPrefix(value, "/")
	parts := strings.SplitN(trimmed, "?", 2)
	decoded, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", storage.ErrInvalidRequest
	}
	if len(parts) == 2 {
		values, parseErr := url.ParseQuery(parts[1])
		if parseErr != nil {
			return "", "", storage.ErrInvalidRequest
		}
		for key := range values {
			if key != "versionId" {
				return "", "", storage.ErrInvalidRequest
			}
		}
	}
	pathParts := strings.SplitN(decoded, "/", 2)
	if len(pathParts) != 2 || pathParts[0] == "" || pathParts[1] == "" {
		return "", "", storage.ErrInvalidRequest
	}
	if !s3.IsValidBucketName(pathParts[0]) {
		return "", "", storage.ErrInvalidRequest
	}
	return pathParts[0], pathParts[1], nil
}

func applyMetadataHeaders(headers http.Header, meta storage.ObjectMetadata) {
	contentType := meta.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	headers.Set("Content-Type", contentType)
	headers.Set("Content-Length", strconv.FormatInt(meta.ContentLength, 10))
	headers.Set("ETag", quoteETag(meta.ETag))
	if meta.VersionID != "" {
		headers.Set("x-amz-version-id", meta.VersionID)
	}
	if meta.DeleteMarker {
		headers.Set("x-amz-delete-marker", "true")
	}
	if !meta.LastModified.IsZero() {
		headers.Set("Last-Modified", meta.LastModified.UTC().Format(http.TimeFormat))
	}
	for k, v := range meta.UserMetadata {
		headers.Set("x-amz-meta-"+k, v)
	}
}

func quoteETag(etag string) string {
	trimmed := strings.Trim(strings.TrimSpace(etag), "\"")
	if trimmed == "" {
		return "\"\""
	}
	return `"` + trimmed + `"`
}

func formatS3XMLTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func applyConditionalHeaders(w http.ResponseWriter, r *http.Request, meta storage.ObjectMetadata) bool {
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		if ifMatch != "*" && !headerContainsETag(ifMatch, meta.ETag) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return true
		}
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if ifNoneMatch == "*" || headerContainsETag(ifNoneMatch, meta.ETag) {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	lastModified := meta.LastModified.UTC().Truncate(time.Second)
	if ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since"); ifUnmodifiedSince != "" {
		if t, ok := parseHTTPDate(ifUnmodifiedSince); ok && lastModified.After(t) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return true
		}
	}
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if t, ok := parseHTTPDate(ifModifiedSince); ok && !lastModified.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	return false
}

func headerContainsETag(headerValue, etag string) bool {
	for _, token := range strings.Split(headerValue, ",") {
		candidate := strings.TrimSpace(token)
		candidate = strings.TrimPrefix(candidate, "W/")
		candidate = strings.Trim(candidate, "\"")
		if candidate == etag {
			return true
		}
	}
	return false
}

func parseHTTPDate(value string) (time.Time, bool) {
	parsed, err := time.Parse(http.TimeFormat, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func (s *Service) isAllowedFromContext(ctx context.Context, action, resource string) bool {
	info, ok := requestContextFrom(ctx)
	if !ok {
		return false
	}
	allowed, err := s.isAuthorizedForOperation(ctx, info.Principal, action, resource, info.Operation, info.PolicyEval)
	return err == nil && allowed
}

func requestContextFrom(ctx context.Context) (requestContext, bool) {
	info, ok := ctx.Value(ctxKey{}).(requestContext)
	return info, ok
}

func (s *Service) isAuthorizedForOperation(ctx context.Context, principal authz.Principal, action, resource string, op s3.Operation, evalCtx policy.EvaluationContext) (bool, error) {
	if !s.Authz.IsAllowed(principal, action, resource) {
		return false, nil
	}
	if !shouldApplyBucketPolicy(op) {
		return true, nil
	}
	if action == "bucket:create" || action == "bucket:delete" {
		return true, nil
	}
	bucket, hasBucket := bucketFromResource(resource)
	if !hasBucket {
		return true, nil
	}
	policyAction, ok := policyActionForAuthAction(action)
	if !ok {
		return true, nil
	}
	policyResource, ok := policyResourceForAuthResource(action, resource)
	if !ok {
		return true, nil
	}
	return s.isAllowedByBucketPolicy(ctx, bucket, principal, policyAction, policyResource, evalCtx)
}

func shouldApplyBucketPolicy(op s3.Operation) bool {
	switch op {
	case s3.OperationUnknown,
		s3.OperationListBuckets,
		s3.OperationCreateBucket,
		s3.OperationGetBucketPolicy,
		s3.OperationPutBucketPolicy,
		s3.OperationDeleteBucketPolicy,
		s3.OperationGetBucketPolicyStatus:
		return false
	default:
		return true
	}
}

func (s *Service) isAllowedByBucketPolicy(ctx context.Context, bucket string, principal authz.Principal, action string, resource string, evalCtx policy.EvaluationContext) (bool, error) {
	raw, err := s.Backend.GetBucketPolicy(ctx, bucket)
	if err != nil {
		if errors.Is(err, storage.ErrNoSuchBucketPolicy) {
			return true, nil
		}
		return false, err
	}
	doc, err := policy.ParseAndValidate(raw, bucket)
	if err != nil {
		return false, err
	}
	decision := policy.Evaluate(doc, policyPrincipalCandidates(principal, evalCtx), action, resource, evalCtx)
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Debug("bucket policy authorization evaluated",
		"bucket", bucket,
		"principal", principal.AccessKey,
		"action", action,
		"resource", resource,
		"secure_transport", evalCtx.SecureTransport,
		"source_ip", sourceIPString(evalCtx.SourceIP),
		"policy_allowed", decision.Allowed,
		"policy_denied", decision.Denied,
	)
	if decision.Denied {
		return false, nil
	}
	return decision.Allowed, nil
}

func policyPrincipalCandidates(principal authz.Principal, evalCtx policy.EvaluationContext) []string {
	out := make([]string, 0, 8)
	seen := map[string]struct{}{}
	appendCandidate := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	appendCandidate(principal.AccessKey)
	appendCandidate(principal.Name)
	if evalCtx.Attributes != nil {
		appendCandidate(evalCtx.Attributes["aws:userid"])
		appendCandidate(evalCtx.Attributes["aws:username"])
		appendCandidate(evalCtx.Attributes["aws:PrincipalArn"])
	}
	return out
}

func (s *Service) policyEvaluationContextFromRequest(r *http.Request, op s3.Operation, principal authz.Principal) policy.EvaluationContext {
	sourceIP := resolveSourceIP(r, s.TrustProxyHeaders)
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	return policy.EvaluationContext{
		SecureTransport: r.TLS != nil,
		SourceIP:        sourceIP,
		Headers:         map[string][]string(r.Header.Clone()),
		Attributes:      policyAttributesFromRequest(r, op, principal, sourceIP, now),
		CurrentTime:     now,
	}
}

func policyAttributesFromRequest(r *http.Request, op s3.Operation, principal authz.Principal, sourceIP net.IP, now time.Time) map[string]string {
	attrs := map[string]string{
		"aws:PrincipalType":    "User",
		"aws:PrincipalAccount": "local",
		"aws:userid":           principal.AccessKey,
		"aws:CurrentTime":      now.UTC().Format(time.RFC3339),
		"s3:authType":          "REST-HEADER",
		"s3:signatureversion":  "AWS4-HMAC-SHA256",
	}
	if principal.Name != "" {
		attrs["aws:username"] = principal.Name
		attrs["aws:PrincipalArn"] = "arn:storas:iam::local:user/" + principal.Name
	} else if principal.AccessKey != "" {
		attrs["aws:PrincipalArn"] = "arn:storas:iam::local:user/" + principal.AccessKey
	}
	if sourceIP != nil {
		attrs["aws:SourceIp"] = sourceIP.String()
	}
	attrs["aws:SecureTransport"] = strconv.FormatBool(r.TLS != nil)

	query := r.URL.Query()
	if value := strings.TrimSpace(query.Get("prefix")); value != "" {
		attrs["s3:prefix"] = value
	}
	if value := strings.TrimSpace(query.Get("delimiter")); value != "" {
		attrs["s3:delimiter"] = value
	}
	if value := strings.TrimSpace(query.Get("max-keys")); value != "" {
		attrs["s3:max-keys"] = value
	}
	if value := strings.TrimSpace(query.Get("versionId")); value != "" {
		attrs["s3:VersionId"] = value
	}
	if value := strings.TrimSpace(r.Header.Get("x-amz-acl")); value != "" {
		attrs["s3:x-amz-acl"] = value
	}
	if dateHeader := strings.TrimSpace(r.Header.Get("X-Amz-Date")); dateHeader != "" {
		if signedAt, err := time.Parse(sigv4.DateFormat, dateHeader); err == nil {
			age := now.UTC().Sub(signedAt.UTC()).Milliseconds()
			if age < 0 {
				age = 0
			}
			attrs["s3:signatureAge"] = strconv.FormatInt(age, 10)
		}
	}
	if op == s3.OperationListObjects || op == s3.OperationListObjectVersions || op == s3.OperationListMultipartUploads {
		if _, ok := attrs["s3:prefix"]; !ok {
			attrs["s3:prefix"] = ""
		}
		if _, ok := attrs["s3:delimiter"]; !ok {
			attrs["s3:delimiter"] = ""
		}
		if _, ok := attrs["s3:max-keys"]; !ok {
			attrs["s3:max-keys"] = "1000"
		}
	}
	return attrs
}

func resolveSourceIP(r *http.Request, trustProxyHeaders bool) net.IP {
	if trustProxyHeaders {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			if ip := parseIPCandidate(first); ip != nil {
				return ip
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			if ip := parseIPCandidate(realIP); ip != nil {
				return ip
			}
		}
	}
	return parseIPCandidate(r.RemoteAddr)
}

func parseIPCandidate(raw string) net.IP {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}
	candidate = strings.Trim(candidate, "[]")
	return net.ParseIP(candidate)
}

func sourceIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func policyActionForAuthAction(action string) (string, bool) {
	switch action {
	case "bucket:list", "bucket:head", "object:list":
		return "s3:ListBucket", true
	case "bucket:create":
		return "s3:PutBucketPolicy", true
	case "bucket:delete":
		return "s3:DeleteBucketPolicy", true
	case "object:get", "object:head":
		return "s3:GetObject", true
	case "object:put", "object:copy":
		return "s3:PutObject", true
	case "object:delete":
		return "s3:DeleteObject", true
	default:
		return "", false
	}
}

func policyResourceForAuthResource(action string, resource string) (string, bool) {
	switch action {
	case "bucket:list", "bucket:head", "bucket:create", "bucket:delete", "object:list":
		bucket, ok := bucketFromResource(resource)
		if !ok {
			return "", false
		}
		return "arn:aws:s3:::" + bucket, true
	default:
		if strings.Contains(resource, "/") {
			return "arn:aws:s3:::" + resource, true
		}
	}
	return "", false
}

func bucketFromResource(resource string) (string, bool) {
	if resource == "" || resource == "*" {
		return "", false
	}
	if idx := strings.IndexByte(resource, '/'); idx >= 0 {
		if idx == 0 {
			return "", false
		}
		return resource[:idx], true
	}
	return resource, true
}

func getSingleQueryValue(q url.Values, key string) (string, error) {
	values, ok := q[key]
	if !ok || len(values) == 0 {
		return "", nil
	}
	first := values[0]
	for _, value := range values[1:] {
		if value != first {
			return "", storage.ErrInvalidRequest
		}
	}
	return first, nil
}

func validateACLCompatibilityHeaders(h http.Header, op s3.Operation) error {
	for _, key := range []string{
		"x-amz-grant-read",
		"x-amz-grant-write",
		"x-amz-grant-read-acp",
		"x-amz-grant-write-acp",
		"x-amz-grant-full-control",
	} {
		if strings.TrimSpace(h.Get(key)) != "" {
			return storage.ErrInvalidRequest
		}
	}
	acl := strings.TrimSpace(h.Get("x-amz-acl"))
	if acl == "" {
		return nil
	}
	allowedOps := map[s3.Operation]struct{}{
		s3.OperationCreateBucket:          {},
		s3.OperationPutObject:             {},
		s3.OperationCopyObject:            {},
		s3.OperationCreateMultipartUpload: {},
		s3.OperationPutBucketACL:          {},
		s3.OperationPutObjectACL:          {},
	}
	if _, ok := allowedOps[op]; !ok {
		return storage.ErrInvalidRequest
	}
	switch strings.ToLower(acl) {
	case "private", "public-read", "public-read-write", "authenticated-read", "bucket-owner-read", "bucket-owner-full-control":
		return nil
	default:
		return storage.ErrInvalidRequest
	}
}

func bodyReaderForContentMD5(r *http.Request, src io.Reader) (io.Reader, func(), error) {
	if info, ok := requestContextFrom(r.Context()); ok && info.Auth != nil && sigv4.IsStreamingPayload(info.Auth.PayloadHash) {
		expectedDecodedLength := int64(-1)
		if raw := strings.TrimSpace(r.Header.Get("X-Amz-Decoded-Content-Length")); raw != "" {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || parsed < 0 {
				return nil, nil, storage.ErrInvalidRequest
			}
			expectedDecodedLength = parsed
		}
		decoded, cleanup, err := sigv4.DecodeStreamingPayload(r.Context(), src, *info.Auth, info.SigningKey, expectedDecodedLength)
		if err != nil {
			return nil, nil, err
		}
		src = decoded
		return bodyReaderForContentMD5WithCleanup(r, src, cleanup)
	}
	return bodyReaderForContentMD5WithCleanup(r, src, nil)
}

func bodyReaderForContentMD5WithCleanup(r *http.Request, src io.Reader, priorCleanup func()) (io.Reader, func(), error) {
	baseCleanup := func() {}
	if priorCleanup != nil {
		baseCleanup = priorCleanup
	}
	contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))
	if contentMD5 == "" {
		return src, baseCleanup, nil
	}
	expected, err := base64.StdEncoding.DecodeString(contentMD5)
	if err != nil || len(expected) != md5.Size {
		baseCleanup()
		return nil, nil, storage.ErrInvalidRequest
	}

	temp, err := os.CreateTemp("", "storas-md5-*")
	if err != nil {
		baseCleanup()
		return nil, nil, err
	}
	cleanup := func() {
		baseCleanup()
		_ = temp.Close()
		_ = os.Remove(temp.Name())
	}
	hasher := md5.New() //nolint:gosec // Content-MD5 protocol compatibility.
	if _, err := io.Copy(io.MultiWriter(temp, hasher), src); err != nil {
		cleanup()
		return nil, nil, err
	}
	if !equalBytes(expected, hasher.Sum(nil)) {
		cleanup()
		return nil, nil, storage.ErrBadDigest
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, err
	}
	return temp, cleanup, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isRequestBodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

func validateUserMetadata(meta map[string]string) error {
	const maxMetadataBytes = 2 * 1024
	total := 0
	for k, v := range meta {
		total += len(k) + len(v)
	}
	if total > maxMetadataBytes {
		return storage.ErrInvalidRequest
	}
	return nil
}

func parseObjectTaggingHeader(raw string) (map[string]string, error) {
	tagging := strings.TrimSpace(raw)
	if tagging == "" {
		return nil, nil
	}
	parsed, err := url.ParseQuery(tagging)
	if err != nil {
		return nil, storage.ErrInvalidRequest
	}
	if len(parsed) > 10 {
		return nil, storage.ErrInvalidRequest
	}
	tags := make(map[string]string, len(parsed))
	for key, values := range parsed {
		if strings.TrimSpace(key) == "" || len(values) != 1 {
			return nil, storage.ErrInvalidRequest
		}
		if len(key) > 128 || len(values[0]) > 256 {
			return nil, storage.ErrInvalidRequest
		}
		tags[key] = values[0]
	}
	return tags, nil
}

func hasCopySourceConditionalHeader(h http.Header) bool {
	for _, key := range []string{
		"x-amz-copy-source-if-match",
		"x-amz-copy-source-if-none-match",
		"x-amz-copy-source-if-modified-since",
		"x-amz-copy-source-if-unmodified-since",
	} {
		if strings.TrimSpace(h.Get(key)) != "" {
			return true
		}
	}
	return false
}

func ifRangeMatches(meta storage.ObjectMetadata, ifRange string) bool {
	if ifRange == "" {
		return true
	}
	if headerContainsETag(ifRange, meta.ETag) {
		return true
	}
	if t, ok := parseHTTPDate(ifRange); ok {
		return !meta.LastModified.UTC().Truncate(time.Second).After(t)
	}
	return false
}
