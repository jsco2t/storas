package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileAppliesDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("storage:\n  data_dir: ./data\nauth:\n  authorization_file: ./authorization.yaml\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}

	if cfg.Server.Region != DefaultRegion {
		t.Fatalf("unexpected region default: %q", cfg.Server.Region)
	}
	if cfg.Health.PathLive != DefaultHealthLive {
		t.Fatalf("unexpected liveness default: %q", cfg.Health.PathLive)
	}
	if cfg.Server.MaxHeaderBytes != DefaultMaxHeader {
		t.Fatalf("unexpected max_header_bytes default: %d", cfg.Server.MaxHeaderBytes)
	}
	if cfg.Server.TrustProxyHeaders {
		t.Fatal("expected trust_proxy_headers default to false")
	}
	if !cfg.Storage.MultipartMaintenance.Enabled {
		t.Fatal("expected multipart maintenance enabled by default")
	}
	if !cfg.Storage.MultipartMaintenance.StartupSweep {
		t.Fatal("expected multipart maintenance startup sweep enabled by default")
	}
	if !cfg.Storage.MultipartMaintenance.RemoveCorruptUploads {
		t.Fatal("expected remove_corrupt_uploads enabled by default")
	}
	if !cfg.Storage.MultipartMaintenance.CleanupTemporaryFiles {
		t.Fatal("expected cleanup_temporary_files enabled by default")
	}
	if cfg.Storage.MultipartMaintenance.MaxRemovalsPerSweep != 0 {
		t.Fatalf("unexpected max_removals_per_sweep default: %d", cfg.Storage.MultipartMaintenance.MaxRemovalsPerSweep)
	}
	if !cfg.Storage.LifecycleMaintenance.Enabled {
		t.Fatal("expected lifecycle maintenance enabled by default")
	}
	if !cfg.Storage.LifecycleMaintenance.StartupSweep {
		t.Fatal("expected lifecycle maintenance startup sweep enabled by default")
	}
	if cfg.Storage.LifecycleMaintenance.SweepIntervalSeconds <= 0 {
		t.Fatalf("expected positive lifecycle sweep interval default, got %d", cfg.Storage.LifecycleMaintenance.SweepIntervalSeconds)
	}
	if cfg.Storage.LifecycleMaintenance.MaxActionsPerSweep < 0 {
		t.Fatalf("expected non-negative lifecycle max actions default, got %d", cfg.Storage.LifecycleMaintenance.MaxActionsPerSweep)
	}
	if cfg.TLS.ACMEDNS.RenewBeforeSeconds <= 0 {
		t.Fatalf("expected positive acme renew_before_seconds default, got %d", cfg.TLS.ACMEDNS.RenewBeforeSeconds)
	}
}

func TestLoadFileParsesTrustProxyHeaders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("server:\n  trust_proxy_headers: true\nstorage:\n  data_dir: ./data\nauth:\n  authorization_file: ./authorization.yaml\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	if !cfg.Server.TrustProxyHeaders {
		t.Fatal("expected trust_proxy_headers to be true")
	}
}

func TestValidateRejectsOversizedMaxBody(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Storage.DataDir = "./data"
	cfg.Auth.AuthorizationFile = "./authorization.yaml"
	cfg.Server.MaxBodyBytes = DefaultMaxBody + 1

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "max_body_bytes") {
		t.Fatalf("expected max_body_bytes error, got: %v", err)
	}
}

func TestValidateManualTLSRequiresExistingFiles(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Storage.DataDir = "./data"
	cfg.Auth.AuthorizationFile = "./authorization.yaml"
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "manual"
	cfg.TLS.CertFile = "missing.crt"
	cfg.TLS.KeyFile = "missing.key"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "tls.cert_file") {
		t.Fatalf("expected tls.cert_file error, got: %v", err)
	}
}

func TestValidateRejectsInvalidMaxHeader(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Storage.DataDir = "./data"
	cfg.Auth.AuthorizationFile = "./authorization.yaml"
	cfg.Server.MaxHeaderBytes = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "max_header_bytes") {
		t.Fatalf("expected max_header_bytes error, got: %v", err)
	}
}

func TestValidateRejectsInvalidMultipartMaintenanceWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Storage.DataDir = "./data"
	cfg.Auth.AuthorizationFile = "./authorization.yaml"
	cfg.Storage.MultipartMaintenance.Enabled = true
	cfg.Storage.MultipartMaintenance.SweepIntervalSeconds = 0
	cfg.Storage.MultipartMaintenance.StaleAfterSeconds = 0
	cfg.Storage.MultipartMaintenance.MaxRemovalsPerSweep = -1
	cfg.Storage.MultipartMaintenance.CleanupTemporaryFiles = true
	cfg.Storage.MultipartMaintenance.TempFileStaleAfterSeconds = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "storage.multipart_maintenance.sweep_interval_seconds") {
		t.Fatalf("expected sweep interval validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "storage.multipart_maintenance.stale_after_seconds") {
		t.Fatalf("expected stale age validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "storage.multipart_maintenance.max_removals_per_sweep") {
		t.Fatalf("expected max removals validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "storage.multipart_maintenance.temp_file_stale_after_seconds") {
		t.Fatalf("expected temp file stale age validation error, got: %v", err)
	}
}

func TestValidateRejectsInvalidLifecycleMaintenanceWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Storage.DataDir = "./data"
	cfg.Auth.AuthorizationFile = "./authorization.yaml"
	cfg.Storage.LifecycleMaintenance.Enabled = true
	cfg.Storage.LifecycleMaintenance.SweepIntervalSeconds = 0
	cfg.Storage.LifecycleMaintenance.MaxActionsPerSweep = -1

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "storage.lifecycle_maintenance.sweep_interval_seconds") {
		t.Fatalf("expected lifecycle sweep interval validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "storage.lifecycle_maintenance.max_actions_per_sweep") {
		t.Fatalf("expected lifecycle max actions validation error, got: %v", err)
	}
}

func TestValidateRejectsInvalidACMERenewWindowWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Storage.DataDir = "./data"
	cfg.Auth.AuthorizationFile = "./authorization.yaml"
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "acme_dns"
	cfg.TLS.ACMEDNS.Email = "ops@example.com"
	cfg.TLS.ACMEDNS.Provider = "cloudflare"
	cfg.TLS.ACMEDNS.Domain = "storage.example.com"
	cfg.TLS.ACMEDNS.Credentials.EnvPrefix = "STORAS_ACME_"
	cfg.TLS.ACMEDNS.PropagationTimeoutSeconds = 0
	cfg.TLS.ACMEDNS.RenewBeforeSeconds = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "tls.acme_dns.propagation_timeout_seconds") {
		t.Fatalf("expected propagation timeout validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tls.acme_dns.renew_before_seconds") {
		t.Fatalf("expected renew_before validation error, got: %v", err)
	}
}
