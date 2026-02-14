package acme

import (
	"context"
	"crypto"
	"errors"
	"strings"

	xacme "golang.org/x/crypto/acme"
)

type xcryptoClient struct {
	client *xacme.Client
}

func NewXCryptoClient(directoryURL string, accountKey crypto.Signer) ACMEClient {
	return &xcryptoClient{client: &xacme.Client{DirectoryURL: directoryURL, Key: accountKey}}
}

func (c *xcryptoClient) Register(ctx context.Context, email string) error {
	contact := []string{}
	if strings.TrimSpace(email) != "" {
		contact = append(contact, "mailto:"+strings.TrimSpace(email))
	}
	_, err := c.client.Register(ctx, &xacme.Account{Contact: contact}, xacme.AcceptTOS)
	if err == nil {
		return nil
	}
	var ae *xacme.Error
	if errors.As(err, &ae) && ae.StatusCode == 409 {
		return nil
	}
	return err
}

func (c *xcryptoClient) NewOrder(ctx context.Context, domain string) (ACMEOrder, error) {
	order, err := c.client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return ACMEOrder{}, err
	}
	return ACMEOrder{URL: order.URI, FinalizeURL: order.FinalizeURL, AuthzURLs: order.AuthzURLs}, nil
}

func (c *xcryptoClient) GetAuthorization(ctx context.Context, authorizationURL string) (ACMEAuthorization, error) {
	auth, err := c.client.GetAuthorization(ctx, authorizationURL)
	if err != nil {
		return ACMEAuthorization{}, err
	}
	challenges := make([]ACMEChallenge, 0, len(auth.Challenges))
	for _, challenge := range auth.Challenges {
		challenges = append(challenges, ACMEChallenge{URL: challenge.URI, Type: challenge.Type, Token: challenge.Token})
	}
	return ACMEAuthorization{Identifier: auth.Identifier.Value, Challenges: challenges}, nil
}

func (c *xcryptoClient) AcceptChallenge(ctx context.Context, challengeURL string) error {
	_, err := c.client.Accept(ctx, &xacme.Challenge{URI: challengeURL})
	return err
}

func (c *xcryptoClient) WaitAuthorization(ctx context.Context, authorizationURL string) error {
	_, err := c.client.WaitAuthorization(ctx, authorizationURL)
	return err
}

func (c *xcryptoClient) FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) ([][]byte, error) {
	der, _, err := c.client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err != nil {
		return nil, err
	}
	return der, nil
}

func (c *xcryptoClient) WaitOrder(ctx context.Context, orderURL string) error {
	_, err := c.client.WaitOrder(ctx, orderURL)
	return err
}

func (c *xcryptoClient) DNS01TXTValue(token string) (string, error) {
	return c.client.DNS01ChallengeRecord(token)
}
