package acme

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
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	accountKeyFileName = "account.key.pem"
	tlsKeyFileName     = "tls.key.pem"
	tlsCertFileName    = "tls.cert.pem"
)

var (
	newACMEClient      = NewXCryptoClient
	waitForTXTRecordFn = waitForTXTRecord
	sleepContextFn     = sleepContext
	retryBackoffFn     = retryBackoff
	jitterDurationFn   = jitterDuration
)

type acmeManager struct {
	cfg      Config
	logger   *slog.Logger
	provider DNSProvider
	client   ACMEClient

	mu   sync.RWMutex
	cert *tls.Certificate

	now func() time.Time

	cancel context.CancelFunc
	done   chan struct{}
}

func NewManager(cfg Config, logger *slog.Logger) (Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	credentials, err := LoadCredentialsFromEnv(cfg.CredentialsPrefix, []string{"API_TOKEN"})
	if err != nil {
		return nil, err
	}
	factory, ok := LookupProvider(cfg.ProviderName)
	if !ok {
		return nil, fmt.Errorf("acme_dns provider %q is not supported", cfg.ProviderName)
	}
	provider, err := factory(ProviderConfig{Credentials: credentials, Logger: logger})
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("acme state path setup failed")
	}
	accountKey, err := loadOrCreateAccountKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	mgr := &acmeManager{
		cfg:      cfg,
		logger:   logger,
		provider: provider,
		client:   newACMEClient(cfg.DirectoryURL, accountKey),
		now:      time.Now,
		done:     make(chan struct{}),
	}

	initial, leaf, err := loadStoredCertificate(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("acme stored certificate load failed")
	}
	if initial == nil || needsRenewal(leaf, mgr.now(), cfg.RenewBefore) {
		issued, issuedLeaf, issueErr := mgr.issueAndStore(context.Background())
		if issueErr != nil {
			if initial == nil {
				return nil, fmt.Errorf("acme initial certificate issuance failed")
			}
			logger.Error("acme certificate renewal failed; keeping existing certificate", "domain", cfg.Domain, "error", sanitizeError(issueErr))
		} else {
			initial = issued
			leaf = issuedLeaf
		}
	}
	if initial == nil || leaf == nil {
		return nil, fmt.Errorf("acme startup certificate unavailable")
	}
	mgr.setCertificate(*initial)

	ctx, cancel := context.WithCancel(context.Background())
	mgr.cancel = cancel
	go mgr.renewLoop(ctx)
	return mgr, nil
}

func (m *acmeManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, fmt.Errorf("acme certificate unavailable")
	}
	return m.cert, nil
}

func (m *acmeManager) Stop() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
}

func (m *acmeManager) renewLoop(ctx context.Context) {
	defer close(m.done)
	failureCount := 0
	for {
		leaf := m.currentLeaf()
		if leaf == nil {
			return
		}
		due := leaf.NotAfter.Add(-m.cfg.RenewBefore)
		wait := time.Until(due)
		if wait < 0 {
			wait = 0
		}

		if !sleepContextFn(ctx, wait) {
			return
		}

		pair, _, err := m.issueAndStore(ctx)
		if err != nil {
			failureCount++
			backoff := retryBackoffFn(failureCount)
			m.logger.Error("acme renewal failed; keeping current certificate", "domain", m.cfg.Domain, "error", sanitizeError(err), "retry_in", backoff.String())
			if !sleepContextFn(ctx, backoff+jitterDurationFn(backoff/5)) {
				return
			}
			continue
		}
		failureCount = 0
		m.setCertificate(*pair)
		m.logger.Info("acme certificate renewed", "domain", m.cfg.Domain)
	}
}

func (m *acmeManager) setCertificate(pair tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pair.Leaf == nil && len(pair.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
			pair.Leaf = leaf
		}
	}
	m.cert = &pair
}

func (m *acmeManager) currentLeaf() *x509.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil
	}
	if m.cert.Leaf != nil {
		return m.cert.Leaf
	}
	if len(m.cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(m.cert.Certificate[0])
	if err != nil {
		return nil
	}
	m.cert.Leaf = leaf
	return leaf
}

func (m *acmeManager) issueAndStore(ctx context.Context) (*tls.Certificate, *x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, m.cfg.PropagationTimeout+2*time.Minute)
	defer cancel()

	if err := m.client.Register(ctx, m.cfg.Email); err != nil {
		return nil, nil, err
	}
	order, err := m.client.NewOrder(ctx, m.cfg.Domain)
	if err != nil {
		return nil, nil, err
	}
	for _, authzURL := range order.AuthzURLs {
		authz, authzErr := m.client.GetAuthorization(ctx, authzURL)
		if authzErr != nil {
			return nil, nil, authzErr
		}
		challenge, found := findDNS01Challenge(authz)
		if !found {
			return nil, nil, fmt.Errorf("dns-01 challenge missing")
		}
		txtValue, txtErr := m.client.DNS01TXTValue(challenge.Token)
		if txtErr != nil {
			return nil, nil, txtErr
		}
		identifier := strings.TrimSpace(authz.Identifier)
		if identifier == "" {
			identifier = m.cfg.Domain
		}
		fqdn := "_acme-challenge." + strings.TrimPrefix(strings.TrimSuffix(identifier, "."), "*.")
		if err := m.provider.Present(ctx, fqdn, txtValue, 60); err != nil {
			return nil, nil, err
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		defer func(fqdn string, txt string) {
			if cleanErr := m.provider.Cleanup(cleanupCtx, fqdn, txt); cleanErr != nil {
				m.logger.Warn("acme challenge cleanup failed", "domain", m.cfg.Domain, "error", sanitizeError(cleanErr))
			}
		}(fqdn, txtValue)

		if err := waitForTXTRecordFn(ctx, fqdn, txtValue, m.cfg.Resolvers, m.cfg.PropagationTimeout); err != nil {
			return nil, nil, err
		}
		if err := m.client.AcceptChallenge(ctx, challenge.URL); err != nil {
			return nil, nil, err
		}
		if err := m.client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, nil, err
		}
	}

	certKey, err := loadOrCreateTLSKey(m.cfg.StateDir)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := buildCSR(certKey, m.cfg.Domain)
	if err != nil {
		return nil, nil, err
	}
	certDER, err := m.client.FinalizeOrder(ctx, order.FinalizeURL, csrDER)
	if err != nil {
		return nil, nil, err
	}
	if err := m.client.WaitOrder(ctx, order.URL); err != nil {
		return nil, nil, err
	}

	certPEM, err := derChainToPEM(certDER)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := marshalECPrivateKeyPEM(certKey)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(filepath.Join(m.cfg.StateDir, tlsCertFileName), certPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(filepath.Join(m.cfg.StateDir, tlsKeyFileName), keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	pair, leaf, err := loadStoredCertificate(m.cfg.StateDir)
	if err != nil {
		return nil, nil, err
	}
	if pair == nil || leaf == nil {
		return nil, nil, fmt.Errorf("acme persisted certificate invalid")
	}
	return pair, leaf, nil
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Email) == "" {
		return fmt.Errorf("acme email is required")
	}
	if strings.TrimSpace(cfg.DirectoryURL) == "" {
		return fmt.Errorf("acme directory_url is required")
	}
	if strings.TrimSpace(cfg.ProviderName) == "" {
		return fmt.Errorf("acme provider is required")
	}
	if strings.TrimSpace(cfg.Domain) == "" {
		return fmt.Errorf("acme domain is required")
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return fmt.Errorf("acme state path is required")
	}
	if cfg.PropagationTimeout <= 0 {
		return fmt.Errorf("acme propagation timeout must be > 0")
	}
	if cfg.RenewBefore <= 0 {
		return fmt.Errorf("acme renew-before window must be > 0")
	}
	return nil
}

func loadStoredCertificate(stateDir string) (*tls.Certificate, *x509.Certificate, error) {
	certPath := filepath.Join(stateDir, tlsCertFileName)
	keyPath := filepath.Join(stateDir, tlsKeyFileName)
	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, fmt.Errorf("stored certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	pair.Leaf = leaf
	return &pair, leaf, nil
}

func loadOrCreateAccountKey(stateDir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(stateDir, accountKeyFileName)
	if key, err := loadECPrivateKey(path); err == nil {
		return key, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pemData, err := marshalECPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pemData, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func loadOrCreateTLSKey(stateDir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(stateDir, tlsKeyFileName)
	if key, err := loadECPrivateKey(path); err == nil {
		return key, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pemData, err := marshalECPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pemData, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsedAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsedAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type")
	}
	return key, nil
}

func marshalECPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func buildCSR(key *ecdsa.PrivateKey, domain string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	return x509.CreateCertificateRequest(rand.Reader, tpl, key)
}

func derChainToPEM(chain [][]byte) ([]byte, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}
	var out []byte
	for _, certDER := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}
	return out, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

func findDNS01Challenge(authz ACMEAuthorization) (ACMEChallenge, bool) {
	for _, challenge := range authz.Challenges {
		if challenge.Type == "dns-01" {
			return challenge, true
		}
	}
	return ACMEChallenge{}, false
}

func waitForTXTRecord(ctx context.Context, fqdn string, expected string, resolvers []string, timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("acme propagation timeout must be > 0")
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if err := checkTXTResolvers(deadlineCtx, fqdn, expected, resolvers); err == nil {
			return nil
		}
		if deadlineCtx.Err() != nil {
			return fmt.Errorf("acme challenge propagation timeout")
		}
		if !sleepContextFn(deadlineCtx, defaultPropagationPollPeriod) {
			return fmt.Errorf("acme challenge propagation timeout")
		}
	}
}

func checkTXTResolvers(ctx context.Context, fqdn string, expected string, resolvers []string) error {
	queryName := strings.TrimSuffix(fqdn, ".")
	resolverList := resolvers
	if len(resolverList) == 0 {
		resolverList = []string{""}
	}
	for _, resolverAddr := range resolverList {
		resolver := buildResolver(resolverAddr)
		txt, err := resolver.LookupTXT(ctx, queryName)
		if err != nil {
			return err
		}
		found := false
		for _, value := range txt {
			if value == expected {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("acme challenge TXT not yet visible")
		}
	}
	return nil
}

func buildResolver(address string) *net.Resolver {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return net.DefaultResolver
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		host = trimmed
		port = "53"
	}
	if host == "" {
		host = trimmed
	}
	endpoint := net.JoinHostPort(host, port)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, endpoint)
		},
	}
}

func needsRenewal(leaf *x509.Certificate, now time.Time, renewBefore time.Duration) bool {
	if leaf == nil {
		return true
	}
	return now.Add(renewBefore).After(leaf.NotAfter)
}

func retryBackoff(failureCount int) time.Duration {
	if failureCount < 1 {
		return defaultBackoffMin
	}
	factor := math.Pow(2, float64(failureCount-1))
	backoff := time.Duration(float64(defaultBackoffMin) * factor)
	if backoff > defaultBackoffMax {
		backoff = defaultBackoffMax
	}
	return backoff
}

func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(base.Nanoseconds()+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, secret := range []string{"api_token", "authorization", "private key", "bearer"} {
		if strings.Contains(strings.ToLower(msg), secret) {
			return "redacted"
		}
	}
	return msg
}
