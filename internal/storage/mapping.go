package storage

import (
	"encoding/base64"
	"fmt"
)

// EncodeKey encodes an arbitrary S3 object key into a filesystem-safe name.
func EncodeKey(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

// DecodeKey restores a key encoded by EncodeKey.
func DecodeKey(encoded string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encoded key: %w", err)
	}
	return string(decoded), nil
}
