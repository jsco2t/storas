package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrInvalidCredentialScope = errors.New("invalid credential scope")
	ErrInvalidAccessKey       = errors.New("invalid access key")
	ErrSignatureMismatch      = errors.New("signature does not match")
)

func ValidateScope(scope CredentialScope, region, service string) error {
	if scope.Region != region {
		return fmt.Errorf("%w: region mismatch", ErrInvalidCredentialScope)
	}
	if scope.Service != service {
		return fmt.Errorf("%w: service mismatch", ErrInvalidCredentialScope)
	}
	if scope.Terminal != "aws4_request" {
		return fmt.Errorf("%w: terminal must be aws4_request", ErrInvalidCredentialScope)
	}
	return nil
}

func SigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func SignatureHex(signingKey []byte, stringToSign string) string {
	sig := hmacSHA256(signingKey, []byte(stringToSign))
	return hex.EncodeToString(sig)
}

func VerifySignature(expected, actual string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	actual = strings.ToLower(strings.TrimSpace(actual))
	if len(expected) == 0 || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func VerifyRequest(r *http.Request, auth RequestAuth, secret, region, service string) error {
	if auth.Authorization.Credential.AccessKey == "" {
		return ErrInvalidAccessKey
	}
	if err := ValidateScope(auth.Authorization.Credential, region, service); err != nil {
		return err
	}
	canonical, err := BuildCanonicalRequest(r, auth.SignedHeaders, auth.PayloadHash)
	if err != nil {
		return err
	}
	stringToSign := BuildStringToSign(canonical, auth.RequestTime, auth.Authorization.Credential)
	signingKey := SigningKey(secret, auth.Authorization.Credential.Date, auth.Authorization.Credential.Region, auth.Authorization.Credential.Service)
	expected := SignatureHex(signingKey, stringToSign)
	if !VerifySignature(expected, auth.Authorization.Signature) {
		return ErrSignatureMismatch
	}
	return nil
}

func hmacSHA256(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}
