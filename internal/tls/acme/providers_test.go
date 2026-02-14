package acme

import (
	"strings"
	"testing"
	"time"
)

func TestLookupProviderCloudflareRegistered(t *testing.T) {
	if _, ok := LookupProvider("cloudflare"); !ok {
		t.Fatal("expected cloudflare provider to be registered")
	}
}

func TestLoadCredentialsFromEnv(t *testing.T) {
	origGetenv := getenv
	t.Cleanup(func() {
		getenv = origGetenv
	})
	getenv = func(key string) string {
		if key == "STORAS_ACME_API_TOKEN" {
			return "token"
		}
		return ""
	}

	creds, err := LoadCredentialsFromEnv("STORAS_ACME_", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("LoadCredentialsFromEnv error: %v", err)
	}
	if creds["API_TOKEN"] != "token" {
		t.Fatalf("unexpected API token value: %q", creds["API_TOKEN"])
	}
}

func TestLoadCredentialsFromEnvMissingValue(t *testing.T) {
	origGetenv := getenv
	t.Cleanup(func() {
		getenv = origGetenv
	})
	getenv = func(string) string { return "" }

	_, err := LoadCredentialsFromEnv("STORAS_ACME_", []string{"API_TOKEN"})
	if err == nil {
		t.Fatal("expected credential loading failure")
	}
	if !strings.Contains(err.Error(), "STORAS_ACME_API_TOKEN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig(t *testing.T) {
	cfg := Config{
		Email:              "ops@example.com",
		DirectoryURL:       "https://example.com/acme/directory",
		ProviderName:       "cloudflare",
		Domain:             "storage.example.com",
		CredentialsPrefix:  "STORAS_ACME_",
		PropagationTimeout: time.Minute,
		StateDir:           t.TempDir(),
		RenewBefore:        12 * time.Hour,
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig error: %v", err)
	}

	cfg.RenewBefore = 0
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected renew-before validation failure")
	}
}
