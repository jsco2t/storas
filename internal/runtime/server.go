package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"storas/internal/config"
	acmetls "storas/internal/tls/acme"
)

type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	stopRenew  func()
}

func New(cfg config.Config, handler http.Handler, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	httpServer := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	srv := &Server{httpServer: httpServer, logger: logger}

	if !cfg.TLS.Enabled {
		return srv, nil
	}

	switch cfg.TLS.Mode {
	case "manual":
		pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("manual tls load failed: invalid tls certificate or key material")
		}
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	case "self_signed":
		pair, err := generateSelfSignedPair(cfg.TLS.SelfSigned.CommonName, cfg.TLS.SelfSigned.ValidDays)
		if err != nil {
			return nil, fmt.Errorf("self-signed cert generation failed: %w", err)
		}
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	case "acme_dns":
		manager, err := newACMEManager(acmetls.Config{
			Email:              cfg.TLS.ACMEDNS.Email,
			DirectoryURL:       cfg.TLS.ACMEDNS.DirectoryURL,
			ProviderName:       cfg.TLS.ACMEDNS.Provider,
			Domain:             cfg.TLS.ACMEDNS.Domain,
			CredentialsPrefix:  cfg.TLS.ACMEDNS.Credentials.EnvPrefix,
			PropagationTimeout: time.Duration(cfg.TLS.ACMEDNS.PropagationTimeoutSeconds) * time.Second,
			Resolvers:          cfg.TLS.ACMEDNS.Resolvers,
			StateDir:           acmeStateDir(cfg),
			RenewBefore:        time.Duration(cfg.TLS.ACMEDNS.RenewBeforeSeconds) * time.Second,
		}, logger)
		if err != nil {
			return nil, err
		}
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: manager.GetCertificate}
		srv.stopRenew = manager.Stop
	default:
		return nil, fmt.Errorf("unsupported tls mode: %s", cfg.TLS.Mode)
	}

	return srv, nil
}

func (s *Server) Start() error {
	if s.httpServer.TLSConfig == nil {
		return s.httpServer.ListenAndServe()
	}
	return s.httpServer.ListenAndServeTLS("", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.stopRenew != nil {
		s.stopRenew()
	}
	return s.httpServer.Shutdown(ctx)
}

var newACMEManager = acmetls.NewManager

func SetACMEManagerFactoryForTesting(factory func(acmetls.Config, *slog.Logger) (acmetls.Manager, error)) func() {
	previous := newACMEManager
	newACMEManager = factory
	return func() {
		newACMEManager = previous
	}
}

func acmeStateDir(cfg config.Config) string {
	domain := strings.ToLower(strings.TrimSpace(cfg.TLS.ACMEDNS.Domain))
	if domain == "" {
		domain = "default"
	}
	domain = strings.ReplaceAll(domain, "*", "_wildcard_")
	domain = strings.ReplaceAll(domain, "/", "_")
	domain = strings.ReplaceAll(domain, "\\", "_")
	domain = strings.Trim(domain, ".")
	if domain == "" {
		domain = "default"
	}
	return filepath.Join(cfg.Storage.DataDir, "system", "acme", domain)
}

func generateSelfSignedPair(commonName string, validDays int) (tls.Certificate, error) {
	certPEM, keyPEM, err := generateSelfSignedPEM(commonName, validDays)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func generateSelfSignedPEM(commonName string, validDays int) ([]byte, []byte, error) {
	if validDays <= 0 {
		validDays = 365
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{commonName, "localhost"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

func EnsureStorageAvailable(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("storage data dir is empty")
	}
	path := filepath.Clean(dir)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create storage dir: %w", err)
	}
	testPath := filepath.Join(path, ".ready-check")
	if err := os.WriteFile(testPath, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("storage dir not writable: %w", err)
	}
	_ = os.Remove(testPath)
	return nil
}
