package acme

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"
)

const (
	DefaultRenewBefore           = 30 * 24 * time.Hour
	defaultBackoffMin            = time.Minute
	defaultBackoffMax            = time.Hour
	defaultPropagationPollPeriod = 2 * time.Second
)

type Config struct {
	Email              string
	DirectoryURL       string
	ProviderName       string
	Domain             string
	CredentialsPrefix  string
	PropagationTimeout time.Duration
	Resolvers          []string
	StateDir           string
	RenewBefore        time.Duration
}

type DNSProvider interface {
	Present(ctx context.Context, fqdn string, value string, ttl int) error
	Cleanup(ctx context.Context, fqdn string, value string) error
}

type ProviderFactory func(cfg ProviderConfig) (DNSProvider, error)

type ProviderConfig struct {
	Credentials map[string]string
	Logger      *slog.Logger
}

type Manager interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Stop()
}

type ACMEOrder struct {
	URL         string
	FinalizeURL string
	AuthzURLs   []string
}

type ACMEChallenge struct {
	URL   string
	Type  string
	Token string
}

type ACMEAuthorization struct {
	Identifier string
	Challenges []ACMEChallenge
}

type ACMEClient interface {
	Register(ctx context.Context, email string) error
	NewOrder(ctx context.Context, domain string) (ACMEOrder, error)
	GetAuthorization(ctx context.Context, authorizationURL string) (ACMEAuthorization, error)
	AcceptChallenge(ctx context.Context, challengeURL string) error
	WaitAuthorization(ctx context.Context, authorizationURL string) error
	FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) ([][]byte, error)
	WaitOrder(ctx context.Context, orderURL string) error
	DNS01TXTValue(token string) (string, error)
}
