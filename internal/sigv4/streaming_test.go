package sigv4

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestDecodeStreamingPayloadValidChain(t *testing.T) {
	t.Parallel()
	auth, key := streamingAuthFixture()
	body := buildStreamingPayload(auth, key, []string{"hello-", "world"})

	out, cleanup, err := DecodeStreamingPayload(context.Background(), strings.NewReader(body), auth, key, int64(len("hello-world")), "")
	if err != nil {
		t.Fatalf("DecodeStreamingPayload error: %v", err)
	}
	defer cleanup()
	decoded, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("read decoded payload: %v", err)
	}
	if string(decoded) != "hello-world" {
		t.Fatalf("unexpected decoded payload: %q", string(decoded))
	}
}

func TestDecodeStreamingPayloadRejectsInvalidSignature(t *testing.T) {
	t.Parallel()
	auth, key := streamingAuthFixture()
	body := buildStreamingPayload(auth, key, []string{"hello"})
	body = strings.Replace(body, "a", "b", 1)

	if _, cleanup, err := DecodeStreamingPayload(context.Background(), strings.NewReader(body), auth, key, -1, ""); err == nil {
		t.Fatal("expected signature mismatch error")
	} else {
		if cleanup != nil {
			cleanup()
		}
	}
}

func TestDecodeStreamingPayloadRejectsFramingErrors(t *testing.T) {
	t.Parallel()
	auth, key := streamingAuthFixture()
	body := buildStreamingPayload(auth, key, []string{"abc"})
	body = strings.Replace(body, "\r\n", "\n", 1)

	if _, cleanup, err := DecodeStreamingPayload(context.Background(), strings.NewReader(body), auth, key, -1, ""); err == nil {
		t.Fatal("expected framing validation error")
	} else if cleanup != nil {
		cleanup()
	}
}

func TestDecodeStreamingPayloadHonorsDecodedLength(t *testing.T) {
	t.Parallel()
	auth, key := streamingAuthFixture()
	body := buildStreamingPayload(auth, key, []string{"abc"})
	if _, cleanup, err := DecodeStreamingPayload(context.Background(), strings.NewReader(body), auth, key, 10, ""); err == nil {
		t.Fatal("expected decoded-length mismatch error")
	} else if cleanup != nil {
		cleanup()
	}
}

func streamingAuthFixture() (RequestAuth, []byte) {
	ts := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	scope := CredentialScope{
		AccessKey: "AKIASTREAM",
		Date:      ts.UTC().Format("20060102"),
		Region:    "us-west-1",
		Service:   "s3",
		Terminal:  "aws4_request",
	}
	seed := strings.Repeat("a", 64)
	auth := RequestAuth{
		RequestTime: ts.UTC(),
		Authorization: Authorization{
			Credential: scope,
			Signature:  seed,
		},
		PayloadHash: StreamingPayload,
	}
	key := SigningKey("stream-secret", scope.Date, scope.Region, scope.Service)
	return auth, key
}

func buildStreamingPayload(auth RequestAuth, signingKey []byte, chunks []string) string {
	var buf bytes.Buffer
	prev := auth.Authorization.Signature
	for _, chunk := range chunks {
		payload := []byte(chunk)
		sig := SignatureHex(signingKey, buildStreamingStringToSign(auth, prev, payload))
		_, _ = fmt.Fprintf(&buf, "%x;chunk-signature=%s\r\n", len(payload), sig)
		_, _ = buf.Write(payload)
		_, _ = buf.WriteString("\r\n")
		prev = sig
	}
	finalSig := SignatureHex(signingKey, buildStreamingStringToSign(auth, prev, nil))
	_, _ = fmt.Fprintf(&buf, "0;chunk-signature=%s\r\n\r\n", finalSig)
	return buf.String()
}
