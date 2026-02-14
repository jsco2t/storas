package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAuthFilePermissionsWarnsOnBroadPermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "authorization.yaml")
	if err := os.WriteFile(path, []byte("users: []\n"), 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	warn, err := CheckAuthFilePermissions(path)
	if err != nil {
		t.Fatalf("CheckAuthFilePermissions error: %v", err)
	}
	if !strings.Contains(warn, "overly broad permissions") {
		t.Fatalf("expected warning for broad permissions, got %q", warn)
	}
}

func TestCheckAuthFilePermissionsNoWarningForSecureMode(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "authorization.yaml")
	if err := os.WriteFile(path, []byte("users: []\n"), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	warn, err := CheckAuthFilePermissions(path)
	if err != nil {
		t.Fatalf("CheckAuthFilePermissions error: %v", err)
	}
	if warn != "" {
		t.Fatalf("expected no warning, got %q", warn)
	}
}
