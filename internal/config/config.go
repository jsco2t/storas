package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultRegion      = "us-west-1"
	DefaultListenAddr  = "0.0.0.0:9000"
	DefaultLogFormat   = "text"
	DefaultMaxBody     = int64(25 * 1024 * 1024 * 1024)
	DefaultMaxHeader   = 1 << 20 // 1 MiB
	DefaultHealthLive  = "/healthz"
	DefaultHealthReady = "/readyz"
	DefaultTLSMode     = "self_signed"
)

var allowedTLSModes = map[string]struct{}{
	"self_signed": {},
	"acme_dns":    {},
	"manual":      {},
}

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Storage StorageConfig `yaml:"storage"`
	Auth    AuthConfig    `yaml:"auth"`
	TLS     TLSConfig     `yaml:"tls"`
	Health  HealthConfig  `yaml:"health"`
}

type ServerConfig struct {
	ListenAddress     string `yaml:"listen_address"`
	Region            string `yaml:"region"`
	LogFormat         string `yaml:"log_format"`
	MaxBodyBytes      int64  `yaml:"max_body_bytes"`
	MaxHeaderBytes    int    `yaml:"max_header_bytes"`
	TrustProxyHeaders bool   `yaml:"trust_proxy_headers"`
}

type StorageConfig struct {
	DataDir              string                            `yaml:"data_dir"`
	MultipartMaintenance StorageMultipartMaintenanceConfig `yaml:"multipart_maintenance"`
	LifecycleMaintenance StorageLifecycleMaintenanceConfig `yaml:"lifecycle_maintenance"`
}

type StorageMultipartMaintenanceConfig struct {
	Enabled                   bool `yaml:"enabled"`
	StartupSweep              bool `yaml:"startup_sweep"`
	SweepIntervalSeconds      int  `yaml:"sweep_interval_seconds"`
	StaleAfterSeconds         int  `yaml:"stale_after_seconds"`
	MaxRemovalsPerSweep       int  `yaml:"max_removals_per_sweep"`
	RemoveCorruptUploads      bool `yaml:"remove_corrupt_uploads"`
	CleanupTemporaryFiles     bool `yaml:"cleanup_temporary_files"`
	TempFileStaleAfterSeconds int  `yaml:"temp_file_stale_after_seconds"`
}

type StorageLifecycleMaintenanceConfig struct {
	Enabled              bool `yaml:"enabled"`
	StartupSweep         bool `yaml:"startup_sweep"`
	SweepIntervalSeconds int  `yaml:"sweep_interval_seconds"`
	MaxActionsPerSweep   int  `yaml:"max_actions_per_sweep"`
	DryRun               bool `yaml:"dry_run"`
}

type AuthConfig struct {
	AuthorizationFile string `yaml:"authorization_file"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"`

	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	SelfSigned TLSSelfSignedConfig `yaml:"self_signed"`
	ACMEDNS    TLSACMEDNSConfig    `yaml:"acme_dns"`
}

type TLSSelfSignedConfig struct {
	CommonName string `yaml:"common_name"`
	ValidDays  int    `yaml:"valid_days"`
}

type TLSACMEDNSConfig struct {
	Email                     string             `yaml:"email"`
	DirectoryURL              string             `yaml:"directory_url"`
	Provider                  string             `yaml:"provider"`
	Domain                    string             `yaml:"domain"`
	PropagationTimeoutSeconds int                `yaml:"propagation_timeout_seconds"`
	RenewBeforeSeconds        int                `yaml:"renew_before_seconds"`
	Resolvers                 []string           `yaml:"resolvers"`
	Credentials               TLSACMECredentials `yaml:"credentials"`
}

type TLSACMECredentials struct {
	EnvPrefix string `yaml:"env_prefix"`
}

type HealthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	PathLive  string `yaml:"path_live"`
	PathReady string `yaml:"path_ready"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddress:  DefaultListenAddr,
			Region:         DefaultRegion,
			LogFormat:      DefaultLogFormat,
			MaxBodyBytes:   DefaultMaxBody,
			MaxHeaderBytes: DefaultMaxHeader,
		},
		Storage: StorageConfig{
			MultipartMaintenance: StorageMultipartMaintenanceConfig{
				Enabled:                   true,
				StartupSweep:              true,
				SweepIntervalSeconds:      300,
				StaleAfterSeconds:         86400,
				MaxRemovalsPerSweep:       0,
				RemoveCorruptUploads:      true,
				CleanupTemporaryFiles:     true,
				TempFileStaleAfterSeconds: 3600,
			},
			LifecycleMaintenance: StorageLifecycleMaintenanceConfig{
				Enabled:              true,
				StartupSweep:         true,
				SweepIntervalSeconds: 300,
				MaxActionsPerSweep:   1000,
				DryRun:               false,
			},
		},
		TLS: TLSConfig{
			Mode: DefaultTLSMode,
			SelfSigned: TLSSelfSignedConfig{
				CommonName: "localhost",
				ValidDays:  365,
			},
			ACMEDNS: TLSACMEDNSConfig{
				DirectoryURL:              "https://acme-v02.api.letsencrypt.org/directory",
				Provider:                  "cloudflare",
				PropagationTimeoutSeconds: 120,
				RenewBeforeSeconds:        2592000,
				Credentials: TLSACMECredentials{
					EnvPrefix: "STORAS_ACME_",
				},
			},
		},
		Health: HealthConfig{
			Enabled:   true,
			PathLive:  DefaultHealthLive,
			PathReady: DefaultHealthReady,
		},
	}
}

func LoadFile(path string) (Config, error) {
	cfg := Default()

	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error

	if c.Server.ListenAddress == "" {
		errs = append(errs, errors.New("config validation: server.listen_address is required"))
	}
	if c.Server.Region == "" {
		errs = append(errs, errors.New("config validation: server.region is required"))
	}
	if c.Server.LogFormat != "text" && c.Server.LogFormat != "json" {
		errs = append(errs, fmt.Errorf("config validation: server.log_format must be one of [text json], got %q", c.Server.LogFormat))
	}
	if c.Server.MaxBodyBytes <= 0 {
		errs = append(errs, errors.New("config validation: server.max_body_bytes must be > 0"))
	}
	if c.Server.MaxBodyBytes > DefaultMaxBody {
		errs = append(errs, fmt.Errorf("config validation: server.max_body_bytes must be <= %d (25 GiB)", DefaultMaxBody))
	}
	if c.Server.MaxHeaderBytes <= 0 {
		errs = append(errs, errors.New("config validation: server.max_header_bytes must be > 0"))
	}
	if c.Storage.DataDir == "" {
		errs = append(errs, errors.New("config validation: storage.data_dir is required"))
	}
	if c.Storage.MultipartMaintenance.Enabled {
		if c.Storage.MultipartMaintenance.SweepIntervalSeconds <= 0 {
			errs = append(errs, errors.New("config validation: storage.multipart_maintenance.sweep_interval_seconds must be > 0 when storage.multipart_maintenance.enabled=true"))
		}
		if c.Storage.MultipartMaintenance.StaleAfterSeconds <= 0 {
			errs = append(errs, errors.New("config validation: storage.multipart_maintenance.stale_after_seconds must be > 0 when storage.multipart_maintenance.enabled=true"))
		}
		if c.Storage.MultipartMaintenance.MaxRemovalsPerSweep < 0 {
			errs = append(errs, errors.New("config validation: storage.multipart_maintenance.max_removals_per_sweep must be >= 0 when storage.multipart_maintenance.enabled=true"))
		}
		if c.Storage.MultipartMaintenance.CleanupTemporaryFiles && c.Storage.MultipartMaintenance.TempFileStaleAfterSeconds <= 0 {
			errs = append(errs, errors.New("config validation: storage.multipart_maintenance.temp_file_stale_after_seconds must be > 0 when storage.multipart_maintenance.cleanup_temporary_files=true"))
		}
	}
	if c.Storage.LifecycleMaintenance.Enabled {
		if c.Storage.LifecycleMaintenance.SweepIntervalSeconds <= 0 {
			errs = append(errs, errors.New("config validation: storage.lifecycle_maintenance.sweep_interval_seconds must be > 0 when storage.lifecycle_maintenance.enabled=true"))
		}
		if c.Storage.LifecycleMaintenance.MaxActionsPerSweep < 0 {
			errs = append(errs, errors.New("config validation: storage.lifecycle_maintenance.max_actions_per_sweep must be >= 0 when storage.lifecycle_maintenance.enabled=true"))
		}
	}
	if c.Auth.AuthorizationFile == "" {
		errs = append(errs, errors.New("config validation: auth.authorization_file is required"))
	}

	errs = append(errs, c.validateTLS()...)
	errs = append(errs, c.validateHealth()...)

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c Config) validateTLS() []error {
	var errs []error
	if !c.TLS.Enabled {
		return errs
	}

	if _, ok := allowedTLSModes[c.TLS.Mode]; !ok {
		errs = append(errs, fmt.Errorf("config validation: tls.mode must be one of [self_signed acme_dns manual], got %q", c.TLS.Mode))
		return errs
	}

	switch c.TLS.Mode {
	case "manual":
		if c.TLS.CertFile == "" {
			errs = append(errs, errors.New("config validation: tls.cert_file is required when tls.mode=manual"))
		}
		if c.TLS.KeyFile == "" {
			errs = append(errs, errors.New("config validation: tls.key_file is required when tls.mode=manual"))
		}
		if c.TLS.CertFile != "" {
			if statErr := validateReadableFile(c.TLS.CertFile); statErr != nil {
				errs = append(errs, fmt.Errorf("config validation: tls.cert_file: %w", statErr))
			}
		}
		if c.TLS.KeyFile != "" {
			if statErr := validateReadableFile(c.TLS.KeyFile); statErr != nil {
				errs = append(errs, fmt.Errorf("config validation: tls.key_file: %w", statErr))
			}
		}
	case "acme_dns":
		if c.TLS.ACMEDNS.Email == "" {
			errs = append(errs, errors.New("config validation: tls.acme_dns.email is required when tls.mode=acme_dns"))
		}
		if c.TLS.ACMEDNS.Provider == "" {
			errs = append(errs, errors.New("config validation: tls.acme_dns.provider is required when tls.mode=acme_dns"))
		}
		if c.TLS.ACMEDNS.Domain == "" {
			errs = append(errs, errors.New("config validation: tls.acme_dns.domain is required when tls.mode=acme_dns"))
		}
		if c.TLS.ACMEDNS.Credentials.EnvPrefix == "" {
			errs = append(errs, errors.New("config validation: tls.acme_dns.credentials.env_prefix is required when tls.mode=acme_dns"))
		}
		if c.TLS.ACMEDNS.PropagationTimeoutSeconds <= 0 {
			errs = append(errs, errors.New("config validation: tls.acme_dns.propagation_timeout_seconds must be > 0 when tls.mode=acme_dns"))
		}
		if c.TLS.ACMEDNS.RenewBeforeSeconds <= 0 {
			errs = append(errs, errors.New("config validation: tls.acme_dns.renew_before_seconds must be > 0 when tls.mode=acme_dns"))
		}
	}

	if c.TLS.Mode == "self_signed" {
		if c.TLS.SelfSigned.CommonName == "" {
			errs = append(errs, errors.New("config validation: tls.self_signed.common_name is required when tls.mode=self_signed"))
		}
		if c.TLS.SelfSigned.ValidDays <= 0 {
			errs = append(errs, errors.New("config validation: tls.self_signed.valid_days must be > 0 when tls.mode=self_signed"))
		}
	}

	return errs
}

func (c Config) validateHealth() []error {
	if !c.Health.Enabled {
		return nil
	}
	var errs []error
	if !strings.HasPrefix(c.Health.PathLive, "/") {
		errs = append(errs, errors.New("config validation: health.path_live must start with '/'"))
	}
	if !strings.HasPrefix(c.Health.PathReady, "/") {
		errs = append(errs, errors.New("config validation: health.path_ready must start with '/'"))
	}
	if c.Health.PathLive == c.Health.PathReady {
		errs = append(errs, errors.New("config validation: health.path_live and health.path_ready must be different"))
	}
	if c.Health.PathLive == "" {
		errs = append(errs, errors.New("config validation: health.path_live is required when health.enabled=true"))
	}
	if c.Health.PathReady == "" {
		errs = append(errs, errors.New("config validation: health.path_ready is required when health.enabled=true"))
	}
	return errs
}

func validateReadableFile(path string) error {
	cleaned := filepath.Clean(path)
	info, err := os.Stat(cleaned)
	if err != nil {
		return fmt.Errorf("%q is not readable: %w", cleaned, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%q points to a directory", cleaned)
	}
	return nil
}
