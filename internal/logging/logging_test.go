package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewDefaultFormatIsText(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := New("text", &buf)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("test message")
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Fatalf("expected text log output to contain message, got: %s", output)
	}
}

func TestNewJSONFormatProducesJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := New("json", &buf)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("json test")
	output := buf.String()
	if !strings.Contains(output, "json test") {
		t.Fatalf("expected JSON log output to contain message, got: %s", output)
	}
	// JSON format should produce a single-line JSON object
	if strings.Contains(output, "\n\n") {
		t.Fatal("expected single-line JSON output")
	}
}

func TestNewNilWriterDefaultsToStdout(t *testing.T) {
	t.Parallel()
	logger := New("text", nil)
	if logger == nil {
		t.Fatal("expected non-nil logger with nil writer")
	}
	// Should not panic
	logger.Info("no panic")
}

func TestNewUnknownFormatDefaultsToText(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := New("unknown", &buf)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("fallback test")
	output := buf.String()
	if !strings.Contains(output, "fallback test") {
		t.Fatalf("expected text-style output for unknown format, got: %s", output)
	}
}
