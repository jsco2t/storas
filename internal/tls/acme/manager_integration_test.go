package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManagerIssuesCertificateWithControllableDoubles(t *testing.T) {
	stateDir := t.TempDir()
	providerName := "fake-dns-flow"
	provider := &fakeDNSProvider{}
	RegisterProvider(providerName, func(cfg ProviderConfig) (DNSProvider, error) {
		if cfg.Credentials["API_TOKEN"] == "" {
			return nil, errors.New("missing token")
		}
		return provider, nil
	})

	origGetenv := getenv
	origNewClient := newACMEClient
	origWait := waitForTXTRecordFn
	t.Cleanup(func() {
		getenv = origGetenv
		newACMEClient = origNewClient
		waitForTXTRecordFn = origWait
	})
	getenv = func(key string) string {
		if key == "TEST_ACME_API_TOKEN" {
			return "token"
		}
		return ""
	}

	client := newFakeACMEClient("storage.example.com")
	newACMEClient = func(string, crypto.Signer) ACMEClient { return client }
	waitForTXTRecordFn = func(_ context.Context, fqdn string, expected string, _ []string, _ time.Duration) error {
		if fqdn != "_acme-challenge.storage.example.com" {
			t.Fatalf("unexpected fqdn: %s", fqdn)
		}
		if expected != "dns-value-token-1" {
			t.Fatalf("unexpected txt value: %s", expected)
		}
		return nil
	}

	mgr, err := NewManager(Config{
		Email:              "ops@example.com",
		DirectoryURL:       "https://acme.test/directory",
		ProviderName:       providerName,
		Domain:             "storage.example.com",
		CredentialsPrefix:  "TEST_ACME_",
		PropagationTimeout: time.Second,
		Resolvers:          []string{"1.1.1.1:53"},
		StateDir:           stateDir,
		RenewBefore:        time.Hour,
	}, nil)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	defer mgr.Stop()

	pair, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate error: %v", err)
	}
	if pair == nil || pair.Leaf == nil || pair.Leaf.Subject.CommonName != "storage.example.com" {
		t.Fatalf("unexpected issued certificate subject: %#v", pair)
	}
	if !provider.presentCalled || !provider.cleanupCalled {
		t.Fatalf("expected provider present+cleanup, got present=%v cleanup=%v", provider.presentCalled, provider.cleanupCalled)
	}

	for _, name := range []string{accountKeyFileName, tlsKeyFileName, tlsCertFileName} {
		if _, statErr := os.Stat(filepath.Join(stateDir, name)); statErr != nil {
			t.Fatalf("expected %s to exist: %v", name, statErr)
		}
	}
}

func TestNewManagerReusesStoredCertificateOnRestart(t *testing.T) {
	stateDir := t.TempDir()
	if err := writeStoredCertificate(stateDir, "storage.example.com", 90*24*time.Hour); err != nil {
		t.Fatalf("writeStoredCertificate: %v", err)
	}

	providerName := "fake-dns-reuse"
	RegisterProvider(providerName, func(_ ProviderConfig) (DNSProvider, error) { return &fakeDNSProvider{}, nil })

	origGetenv := getenv
	origNewClient := newACMEClient
	t.Cleanup(func() {
		getenv = origGetenv
		newACMEClient = origNewClient
	})
	getenv = func(key string) string {
		if key == "TEST_ACME_API_TOKEN" {
			return "token"
		}
		return ""
	}

	client := newFakeACMEClient("storage.example.com")
	newACMEClient = func(string, crypto.Signer) ACMEClient { return client }

	cfg := Config{
		Email:              "ops@example.com",
		DirectoryURL:       "https://acme.test/directory",
		ProviderName:       providerName,
		Domain:             "storage.example.com",
		CredentialsPrefix:  "TEST_ACME_",
		PropagationTimeout: time.Second,
		StateDir:           stateDir,
		RenewBefore:        24 * time.Hour,
	}

	mgr1, err := NewManager(cfg, nil)
	if err != nil {
		t.Fatalf("first NewManager error: %v", err)
	}
	mgr1.Stop()

	mgr2, err := NewManager(cfg, nil)
	if err != nil {
		t.Fatalf("second NewManager error: %v", err)
	}
	mgr2.Stop()

	if client.newOrderCalls != 0 {
		t.Fatalf("expected no issuance when reusing stored cert, got newOrderCalls=%d", client.newOrderCalls)
	}
}

func TestNewManagerKeepsServingStoredCertificateIfRenewalFails(t *testing.T) {
	stateDir := t.TempDir()
	if err := writeStoredCertificate(stateDir, "existing.example.com", 2*time.Minute); err != nil {
		t.Fatalf("writeStoredCertificate: %v", err)
	}

	providerName := "fake-dns-fallback"
	RegisterProvider(providerName, func(_ ProviderConfig) (DNSProvider, error) { return &fakeDNSProvider{}, nil })

	origGetenv := getenv
	origNewClient := newACMEClient
	t.Cleanup(func() {
		getenv = origGetenv
		newACMEClient = origNewClient
	})
	getenv = func(key string) string {
		if key == "TEST_ACME_API_TOKEN" {
			return "token"
		}
		return ""
	}
	client := newFakeACMEClient("storage.example.com")
	client.registerErr = errors.New("simulated renewal failure")
	newACMEClient = func(string, crypto.Signer) ACMEClient { return client }

	mgr, err := NewManager(Config{
		Email:              "ops@example.com",
		DirectoryURL:       "https://acme.test/directory",
		ProviderName:       providerName,
		Domain:             "storage.example.com",
		CredentialsPrefix:  "TEST_ACME_",
		PropagationTimeout: time.Second,
		StateDir:           stateDir,
		RenewBefore:        24 * time.Hour,
	}, nil)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	defer mgr.Stop()

	pair, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate error: %v", err)
	}
	if pair.Leaf == nil || pair.Leaf.Subject.CommonName != "existing.example.com" {
		t.Fatalf("expected fallback to existing cert, got CN=%v", pair.Leaf.Subject.CommonName)
	}
}

type fakeDNSProvider struct {
	presentCalled bool
	cleanupCalled bool
}

func (f *fakeDNSProvider) Present(_ context.Context, _ string, _ string, _ int) error {
	f.presentCalled = true
	return nil
}

func (f *fakeDNSProvider) Cleanup(_ context.Context, _ string, _ string) error {
	f.cleanupCalled = true
	return nil
}

type fakeACMEClient struct {
	domain string

	registerErr error

	newOrderCalls int
}

func newFakeACMEClient(domain string) *fakeACMEClient {
	return &fakeACMEClient{domain: domain}
}

func (f *fakeACMEClient) Register(context.Context, string) error {
	return f.registerErr
}

func (f *fakeACMEClient) NewOrder(context.Context, string) (ACMEOrder, error) {
	f.newOrderCalls++
	return ACMEOrder{URL: "order-1", FinalizeURL: "finalize-1", AuthzURLs: []string{"authz-1"}}, nil
}

func (f *fakeACMEClient) GetAuthorization(context.Context, string) (ACMEAuthorization, error) {
	return ACMEAuthorization{
		Identifier: f.domain,
		Challenges: []ACMEChallenge{{URL: "challenge-1", Type: "dns-01", Token: "token-1"}},
	}, nil
}

func (f *fakeACMEClient) AcceptChallenge(context.Context, string) error { return nil }

func (f *fakeACMEClient) WaitAuthorization(context.Context, string) error { return nil }

func (f *fakeACMEClient) FinalizeOrder(_ context.Context, _ string, csrDER []byte) ([][]byte, error) {
	certDER, err := issueCertFromCSRDER(csrDER, f.domain, 90*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return [][]byte{certDER}, nil
}

func (f *fakeACMEClient) WaitOrder(context.Context, string) error { return nil }

func (f *fakeACMEClient) DNS01TXTValue(token string) (string, error) {
	return "dns-value-" + token, nil
}

func writeStoredCertificate(stateDir string, cn string, validFor time.Duration) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	certDER, err := issueSelfSignedDERWithKey(cn, validFor, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(stateDir, tlsCertFileName), certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stateDir, tlsKeyFileName), keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

func issueSelfSignedDER(cn string, validFor time.Duration) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return issueSelfSignedDERWithKey(cn, validFor, key)
}

func issueSelfSignedDERWithKey(cn string, validFor time.Duration, key *ecdsa.PrivateKey) ([]byte, error) {
	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(validFor)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
}

func issueCertFromCSRDER(csrDER []byte, cn string, validFor time.Duration) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(validFor)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return x509.CreateCertificate(rand.Reader, tpl, tpl, csr.PublicKey, caKey)
}
