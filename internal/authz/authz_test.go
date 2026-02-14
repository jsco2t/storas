package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileRejectsDuplicateAccessKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorization.yaml")
	content := `users:
  - name: user-a
    access_key: KEY1
    secret_key: secret-a
    allow:
      - action: bucket:list
        resource: "*"
  - name: user-b
    access_key: KEY1
    secret_key: secret-b
    allow:
      - action: bucket:list
        resource: "*"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected duplicate key validation error")
	}
	if !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate error, got: %v", err)
	}
}

func TestIsAllowedDenyByDefault(t *testing.T) {
	t.Parallel()
	engine := &Engine{usersByKey: map[string]User{
		"KEY1": {
			Name:      "backup-agent",
			AccessKey: "KEY1",
			SecretKey: "secret",
			Allow: []Rule{
				{Action: "object:get", Resource: "backup-*/*"},
			},
		},
	}}

	principal, ok := engine.ResolvePrincipal("KEY1")
	if !ok {
		t.Fatal("expected principal resolution")
	}
	if !engine.IsAllowed(principal, "object:get", "backup-01/dir/file.txt") {
		t.Fatal("expected allowed object:get action")
	}
	if engine.IsAllowed(principal, "object:put", "backup-01/dir/file.txt") {
		t.Fatal("expected deny-by-default for unmatched action")
	}
}

func TestMatchResourceWildcard(t *testing.T) {
	t.Parallel()
	if !MatchResource("backup-*/*", "backup-prod/path/to/object.txt") {
		t.Fatal("expected wildcard to match nested path")
	}
	if MatchResource("logs-*/*", "backup-prod/path/to/object.txt") {
		t.Fatal("did not expect unrelated pattern to match")
	}
}
