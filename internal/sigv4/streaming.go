package sigv4

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const streamingAlgorithm = "AWS4-HMAC-SHA256-PAYLOAD"

func DecodeStreamingPayload(ctx context.Context, src io.Reader, auth RequestAuth, signingKey []byte, expectedDecodedLength int64) (io.Reader, func(), error) {
	if !IsStreamingPayload(auth.PayloadHash) {
		return src, func() {}, nil
	}
	if len(signingKey) == 0 {
		return nil, nil, ErrInvalidRequestPayload
	}

	tmp, err := os.CreateTemp("", "storas-streaming-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}

	reader := bufio.NewReader(src)
	prevSignature := strings.ToLower(strings.TrimSpace(auth.Authorization.Signature))
	if len(prevSignature) != 64 {
		cleanup()
		return nil, nil, ErrInvalidRequestPayload
	}
	decodedLength := int64(0)

	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, nil, err
		}
		chunkSize, chunkSignature, err := readChunkHeader(reader)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		chunk, err := readChunkData(reader, chunkSize)
		if err != nil {
			cleanup()
			return nil, nil, err
		}

		expectedSig := SignatureHex(signingKey, buildStreamingStringToSign(auth, prevSignature, chunk))
		if !VerifySignature(expectedSig, chunkSignature) {
			cleanup()
			return nil, nil, ErrSignatureMismatch
		}
		prevSignature = strings.ToLower(chunkSignature)

		if chunkSize == 0 {
			break
		}
		if _, err := tmp.Write(chunk); err != nil {
			cleanup()
			return nil, nil, err
		}
		decodedLength += int64(len(chunk))
	}

	if expectedDecodedLength >= 0 && decodedLength != expectedDecodedLength {
		cleanup()
		return nil, nil, ErrInvalidRequestPayload
	}

	if _, err := reader.Peek(1); err != io.EOF {
		cleanup()
		return nil, nil, ErrInvalidRequestPayload
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, err
	}
	return tmp, cleanup, nil
}

var ErrInvalidRequestPayload = ErrInvalidPayloadHash

func readChunkHeader(r *bufio.Reader) (int64, string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return 0, "", ErrInvalidRequestPayload
		}
		return 0, "", err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return 0, "", ErrInvalidRequestPayload
	}
	line = strings.TrimSuffix(line, "\r\n")
	parts := strings.Split(line, ";")
	if len(parts) != 2 {
		return 0, "", ErrInvalidRequestPayload
	}
	size, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil || size < 0 {
		return 0, "", ErrInvalidRequestPayload
	}
	const signaturePrefix = "chunk-signature="
	if !strings.HasPrefix(parts[1], signaturePrefix) {
		return 0, "", ErrInvalidRequestPayload
	}
	sig := strings.TrimSpace(strings.TrimPrefix(parts[1], signaturePrefix))
	if len(sig) != 64 {
		return 0, "", ErrInvalidRequestPayload
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return 0, "", ErrInvalidRequestPayload
	}
	return size, sig, nil
}

func readChunkData(r *bufio.Reader, size int64) ([]byte, error) {
	chunk := make([]byte, size)
	if _, err := io.ReadFull(r, chunk); err != nil {
		return nil, ErrInvalidRequestPayload
	}
	ending := []byte{0, 0}
	if _, err := io.ReadFull(r, ending); err != nil {
		return nil, ErrInvalidRequestPayload
	}
	if ending[0] != '\r' || ending[1] != '\n' {
		return nil, ErrInvalidRequestPayload
	}
	return chunk, nil
}

func buildStreamingStringToSign(auth RequestAuth, previousSignature string, chunk []byte) string {
	emptyHash := sha256Hex(nil)
	scope := fmt.Sprintf("%s/%s/%s/%s", auth.Authorization.Credential.Date, auth.Authorization.Credential.Region, auth.Authorization.Credential.Service, auth.Authorization.Credential.Terminal)
	return strings.Join([]string{
		streamingAlgorithm,
		auth.RequestTime.UTC().Format(DateFormat),
		scope,
		previousSignature,
		emptyHash,
		sha256Hex(chunk),
	}, "\n")
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
