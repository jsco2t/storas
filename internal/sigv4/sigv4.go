package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	AuthHeaderPrefix = "AWS4-HMAC-SHA256"
	DateFormat       = "20060102T150405Z"
	StreamingPayload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
)

var (
	ErrMalformedAuthorization = errors.New("malformed authorization header")
	ErrInvalidSignedHeaders   = errors.New("invalid signed headers")
	ErrInvalidAmzDate         = errors.New("invalid x-amz-date")
	ErrClockSkew              = errors.New("request time skew too large")
	ErrInvalidPayloadHash     = errors.New("invalid payload hash")
	ErrUnsupportedPayloadMode = errors.New("unsupported payload mode")
)

type CredentialScope struct {
	AccessKey string
	Date      string
	Region    string
	Service   string
	Terminal  string
}

type Authorization struct {
	Algorithm     string
	Credential    CredentialScope
	SignedHeaders []string
	Signature     string
}

type AuthMode string

const (
	AuthModeHeader  AuthMode = "header"
	AuthModePresign AuthMode = "presign"
)

type RequestAuth struct {
	Mode          AuthMode
	Authorization Authorization
	RequestTime   time.Time
	SignedHeaders []string
	PayloadHash   string
}

func ParseAuthorizationHeader(value string) (Authorization, error) {
	if !strings.HasPrefix(value, AuthHeaderPrefix+" ") {
		return Authorization{}, ErrMalformedAuthorization
	}
	rest := strings.TrimPrefix(value, AuthHeaderPrefix+" ")

	fields := strings.Split(rest, ",")
	parts := map[string]string{}
	for _, field := range fields {
		kv := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(kv) != 2 {
			return Authorization{}, ErrMalformedAuthorization
		}
		parts[kv[0]] = kv[1]
	}

	scope, err := parseCredentialScope(parts["Credential"])
	if err != nil {
		return Authorization{}, err
	}
	signedHeaders, err := ParseSignedHeaders(parts["SignedHeaders"])
	if err != nil {
		return Authorization{}, err
	}
	signature := strings.TrimSpace(parts["Signature"])
	if signature == "" {
		return Authorization{}, ErrMalformedAuthorization
	}

	return Authorization{
		Algorithm:     AuthHeaderPrefix,
		Credential:    scope,
		SignedHeaders: signedHeaders,
		Signature:     signature,
	}, nil
}

func ParseSignedHeaders(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrInvalidSignedHeaders
	}
	headers := strings.Split(value, ";")
	for _, header := range headers {
		h := strings.TrimSpace(header)
		if h == "" || strings.ToLower(h) != h {
			return nil, ErrInvalidSignedHeaders
		}
	}
	return headers, nil
}

func ParseAmzDate(value string, now time.Time, allowedSkew time.Duration) (time.Time, error) {
	parsed, err := time.Parse(DateFormat, value)
	if err != nil {
		return time.Time{}, ErrInvalidAmzDate
	}
	if allowedSkew > 0 {
		delta := now.Sub(parsed)
		if delta < 0 {
			delta = -delta
		}
		if delta > allowedSkew {
			return time.Time{}, ErrClockSkew
		}
	}
	return parsed, nil
}

func ParseRequestAuth(r *http.Request, now time.Time, allowedSkew time.Duration) (RequestAuth, error) {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		auth, err := ParseAuthorizationHeader(authHeader)
		if err != nil {
			return RequestAuth{}, err
		}
		t, err := ParseAmzDate(r.Header.Get("X-Amz-Date"), now, allowedSkew)
		if err != nil {
			return RequestAuth{}, err
		}
		payloadHash := r.Header.Get("X-Amz-Content-Sha256")
		if payloadHash == "" {
			payloadHash = "UNSIGNED-PAYLOAD"
		}
		if err := validatePayloadHash(payloadHash); err != nil {
			return RequestAuth{}, err
		}
		return RequestAuth{Mode: AuthModeHeader, Authorization: auth, RequestTime: t, SignedHeaders: auth.SignedHeaders, PayloadHash: payloadHash}, nil
	}

	query := r.URL.Query()
	if query.Get("X-Amz-Algorithm") == AuthHeaderPrefix {
		scope, err := parseCredentialScope(query.Get("X-Amz-Credential"))
		if err != nil {
			return RequestAuth{}, err
		}
		signedHeaders, err := ParseSignedHeaders(query.Get("X-Amz-SignedHeaders"))
		if err != nil {
			return RequestAuth{}, err
		}
		t, err := ParseAmzDate(query.Get("X-Amz-Date"), now, allowedSkew)
		if err != nil {
			return RequestAuth{}, err
		}
		auth := Authorization{
			Algorithm:     AuthHeaderPrefix,
			Credential:    scope,
			SignedHeaders: signedHeaders,
			Signature:     query.Get("X-Amz-Signature"),
		}
		return RequestAuth{Mode: AuthModePresign, Authorization: auth, RequestTime: t, SignedHeaders: signedHeaders, PayloadHash: "UNSIGNED-PAYLOAD"}, nil
	}

	return RequestAuth{}, ErrMalformedAuthorization
}

func BuildCanonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) (string, error) {
	if len(signedHeaders) == 0 {
		return "", ErrInvalidSignedHeaders
	}
	if payloadHash == "" {
		h := sha256.Sum256(nil)
		payloadHash = hex.EncodeToString(h[:])
	}

	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = r.URL.EscapedPath()
	}
	canonURI := canonicalURI(rawPath)
	canonQuery := canonicalQuery(r.URL.Query())
	canonHeaders, signed := canonicalHeaders(r.Header, r.Host, signedHeaders)

	canonical := strings.Join([]string{
		r.Method,
		canonURI,
		canonQuery,
		canonHeaders,
		signed,
		payloadHash,
	}, "\n")
	return canonical, nil
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	for i := range parts {
		decoded := parts[i]
		if unescaped, err := url.PathUnescape(parts[i]); err == nil {
			decoded = unescaped
		}
		parts[i] = s3Encode(decoded, true)
	}
	result := strings.Join(parts, "/")
	if !strings.HasPrefix(result, "/") {
		result = "/" + result
	}
	return result
}

func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key == "X-Amz-Signature" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		vals := values[key]
		sort.Strings(vals)
		for _, v := range vals {
			pairs = append(pairs, s3Encode(key, true)+"="+s3Encode(v, true))
		}
	}
	return strings.Join(pairs, "&")
}

func validatePayloadHash(value string) error {
	if value == "UNSIGNED-PAYLOAD" {
		return nil
	}
	if value == StreamingPayload {
		return nil
	}
	if len(value) != 64 {
		return ErrInvalidPayloadHash
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return ErrInvalidPayloadHash
	}
	return nil
}

func IsStreamingPayload(value string) bool {
	return value == StreamingPayload
}

func s3Encode(value string, encodeSlash bool) string {
	const hexChars = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(value) * 3)
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexChars[c>>4])
		b.WriteByte(hexChars[c&0x0F])
	}
	return b.String()
}

func canonicalHeaders(headers http.Header, host string, signedHeaders []string) (string, string) {
	normalized := make([]string, 0, len(signedHeaders))
	for _, signed := range signedHeaders {
		lower := strings.ToLower(strings.TrimSpace(signed))
		var value string
		if lower == "host" {
			value = host
		} else {
			rawValues := headers.Values(http.CanonicalHeaderKey(lower))
			cleanValues := make([]string, 0, len(rawValues))
			for _, raw := range rawValues {
				cleanValues = append(cleanValues, strings.Join(strings.Fields(raw), " "))
			}
			value = strings.Join(cleanValues, ",")
		}
		value = strings.Join(strings.Fields(value), " ")
		normalized = append(normalized, lower+":"+value)
	}
	return strings.Join(normalized, "\n") + "\n", strings.Join(signedHeaders, ";")
}

func parseCredentialScope(value string) (CredentialScope, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 5 {
		return CredentialScope{}, ErrMalformedAuthorization
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" || parts[4] == "" {
		return CredentialScope{}, ErrMalformedAuthorization
	}
	return CredentialScope{
		AccessKey: parts[0],
		Date:      parts[1],
		Region:    parts[2],
		Service:   parts[3],
		Terminal:  parts[4],
	}, nil
}

func BuildStringToSign(canonicalRequest string, requestTime time.Time, scope CredentialScope) string {
	h := sha256.Sum256([]byte(canonicalRequest))
	canonicalHash := hex.EncodeToString(h[:])

	return strings.Join([]string{
		AuthHeaderPrefix,
		requestTime.UTC().Format(DateFormat),
		fmt.Sprintf("%s/%s/%s/%s", scope.Date, scope.Region, scope.Service, scope.Terminal),
		canonicalHash,
	}, "\n")
}
