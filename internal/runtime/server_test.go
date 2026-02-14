package runtime

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"storas/internal/config"
	acmetls "storas/internal/tls/acme"
)

func TestNewHTTPMode(t *testing.T) {
	t.Parallel()
	cfg := baseConfig(t)
	cfg.TLS.Enabled = false

	srv, err := New(cfg, http.NewServeMux(), nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if srv.httpServer.TLSConfig != nil {
		t.Fatal("expected nil TLS config")
	}
	if srv.httpServer.MaxHeaderBytes != cfg.Server.MaxHeaderBytes {
		t.Fatalf("unexpected MaxHeaderBytes: got=%d want=%d", srv.httpServer.MaxHeaderBytes, cfg.Server.MaxHeaderBytes)
	}
}

func TestNewSelfSignedMode(t *testing.T) {
	t.Parallel()
	cfg := baseConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "self_signed"
	cfg.TLS.SelfSigned.CommonName = "localhost"
	cfg.TLS.SelfSigned.ValidDays = 1

	srv, err := New(cfg, http.NewServeMux(), nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if srv.httpServer.TLSConfig == nil || len(srv.httpServer.TLSConfig.Certificates) == 0 {
		t.Fatal("expected self-signed certificate in TLS config")
	}
}

func TestNewManualMode(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, err := generateSelfSignedPEM("localhost", 1)
	if err != nil {
		t.Fatalf("generateSelfSignedPEM error: %v", err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	cfg := baseConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "manual"
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile

	srv, err := New(cfg, http.NewServeMux(), nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if srv.httpServer.TLSConfig == nil || len(srv.httpServer.TLSConfig.Certificates) == 0 {
		t.Fatal("expected manual certificate in TLS config")
	}
}

func TestManualTLSLoadErrorDoesNotExposeKeyContents(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, []byte("invalid-cert"), 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	secretKeyContents := "PRIVATE-KEY-SHOULD-NOT-LEAK"
	if err := os.WriteFile(keyFile, []byte(secretKeyContents), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	cfg := baseConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "manual"
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile

	_, err := New(cfg, http.NewServeMux(), nil)
	if err == nil {
		t.Fatal("expected manual tls load failure")
	}
	if strings.Contains(err.Error(), secretKeyContents) {
		t.Fatalf("error leaked key contents: %v", err)
	}
}

func TestNewACMEDNSDiagnosticsAndRenewalHook(t *testing.T) {
	cfg := baseConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "acme_dns"
	cfg.TLS.ACMEDNS.Provider = "cloudflare"
	cfg.TLS.ACMEDNS.Domain = "example.com"
	cfg.TLS.ACMEDNS.Credentials.EnvPrefix = "STORAS_ACME_"
	cfg.TLS.ACMEDNS.RenewBeforeSeconds = 3600
	cfg.TLS.ACMEDNS.PropagationTimeoutSeconds = 60

	origFactory := newACMEManager
	t.Cleanup(func() {
		newACMEManager = origFactory
	})
	newACMEManager = func(cfg acmetls.Config, _ *slog.Logger) (acmetls.Manager, error) {
		if cfg.CredentialsPrefix == "" {
			return nil, fmt.Errorf("missing credentials env prefix")
		}
		if os.Getenv(cfg.CredentialsPrefix+"API_TOKEN") == "" {
			return nil, fmt.Errorf("missing API token")
		}
		return fakeACMEManager{}, nil
	}

	if _, err := New(cfg, http.NewServeMux(), nil); err == nil || !strings.Contains(err.Error(), "missing API token") {
		t.Fatalf("expected startup diagnostics error without ACME credentials, got: %v", err)
	}

	t.Setenv("STORAS_ACME_API_TOKEN", "token")
	srv, err := New(cfg, http.NewServeMux(), nil)
	if err != nil {
		t.Fatalf("New error with ACME env configured: %v", err)
	}
	if srv.httpServer.TLSConfig == nil || srv.httpServer.TLSConfig.GetCertificate == nil {
		t.Fatal("expected dynamic TLS config with GetCertificate in ACME mode")
	}
	if srv.stopRenew == nil {
		t.Fatal("expected renewal lifecycle hook in ACME mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func TestACMEDNSCertificateSwapHasNoDowntime(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.TLS.Enabled = true
	cfg.TLS.Mode = "acme_dns"
	cfg.TLS.ACMEDNS.Provider = "cloudflare"
	cfg.TLS.ACMEDNS.Domain = "storage.example.com"
	cfg.TLS.ACMEDNS.Credentials.EnvPrefix = "STORAS_ACME_"
	cfg.TLS.ACMEDNS.RenewBeforeSeconds = 3600
	cfg.TLS.ACMEDNS.PropagationTimeoutSeconds = 60
	t.Setenv("STORAS_ACME_API_TOKEN", "token")

	initial := mustCert(t, "first.example.com")
	rotated := mustCert(t, "second.example.com")
	store := &rotatingTestCertStore{current: initial}

	restoreFactory := SetACMEManagerFactoryForTesting(func(acmetls.Config, *slog.Logger) (acmetls.Manager, error) {
		return &rotatingTestACMEManager{store: store}, nil
	})
	defer restoreFactory()

	srv, err := New(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}), nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.Server.ListenAddress)
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() { done <- srv.httpServer.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	firstBody, firstCN := httpsRequestAndPeerCN(t, ln.Addr().String())
	if firstBody != "ok" {
		t.Fatalf("unexpected first response body: %q", firstBody)
	}
	if firstCN != "first.example.com" {
		t.Fatalf("unexpected first certificate CN: %q", firstCN)
	}

	store.set(rotated)

	secondBody, secondCN := httpsRequestAndPeerCN(t, ln.Addr().String())
	if secondBody != "ok" {
		t.Fatalf("unexpected second response body: %q", secondBody)
	}
	if secondCN != "second.example.com" {
		t.Fatalf("unexpected rotated certificate CN: %q", secondCN)
	}
}

type fakeACMEManager struct{}

func (fakeACMEManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &tls.Certificate{}, nil
}

func (fakeACMEManager) Stop() {}

type rotatingTestACMEManager struct {
	store *rotatingTestCertStore
}

func (m *rotatingTestACMEManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.store.get(), nil
}

func (*rotatingTestACMEManager) Stop() {}

type rotatingTestCertStore struct {
	mu      sync.RWMutex
	current tls.Certificate
}

func (s *rotatingTestCertStore) set(cert tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = cert
}

func (s *rotatingTestCertStore) get() *tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert := s.current
	return &cert
}

func mustCert(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := generateSelfSignedPEM(commonName, 1)
	if err != nil {
		t.Fatalf("generateSelfSignedPEM error: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair error: %v", err)
	}
	return pair
}

func httpsRequestAndPeerCN(t *testing.T, addr string) (string, string) {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("https request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("missing peer certificate")
	}
	return string(body), resp.TLS.PeerCertificates[0].Subject.CommonName
}

func TestEnsureStorageAvailable(t *testing.T) {
	t.Parallel()
	if err := EnsureStorageAvailable(filepath.Join(t.TempDir(), "data")); err != nil {
		t.Fatalf("EnsureStorageAvailable error: %v", err)
	}
	if err := EnsureStorageAvailable(""); err == nil {
		t.Fatal("expected error for empty storage path")
	}
}

func TestServerEnforcesHeaderSizeLimit(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Server.MaxHeaderBytes = 256
	cfg.TLS.Enabled = false

	srv, err := New(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.Server.ListenAddress)
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		done <- srv.httpServer.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nX-Large: %s\r\n\r\n", ln.Addr().String(), strings.Repeat("a", 64*1024))
	if err != nil {
		t.Fatalf("write request error: %v", err)
	}

	statusLine, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read response status line error: %v", err)
	}
	if !strings.Contains(statusLine, "431") {
		t.Fatalf("unexpected status line: %q", statusLine)
	}
}

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Storage.DataDir = t.TempDir()
	cfg.Auth.AuthorizationFile = filepath.Join(t.TempDir(), "authorization.yaml")
	return cfg
}
