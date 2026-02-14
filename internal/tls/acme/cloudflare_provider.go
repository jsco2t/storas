package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const cloudflareDefaultAPIBase = "https://api.cloudflare.com/client/v4"

var (
	cloudflareAPIBase    = cloudflareDefaultAPIBase
	cloudflareRetrySleep = time.Sleep
)

type cloudflareProvider struct {
	httpClient *http.Client
	logger     *slog.Logger
	token      string

	mu        sync.Mutex
	recordIDs map[string]string
}

type cloudflareEnvelope[T any] struct {
	Success bool    `json:"success"`
	Errors  []cfErr `json:"errors"`
	Result  T       `json:"result"`
}

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func init() {
	RegisterProvider("cloudflare", func(cfg ProviderConfig) (DNSProvider, error) {
		token := strings.TrimSpace(cfg.Credentials["API_TOKEN"])
		if token == "" {
			return nil, fmt.Errorf("cloudflare provider requires API_TOKEN credential")
		}
		logger := cfg.Logger
		if logger == nil {
			logger = slog.Default()
		}
		return &cloudflareProvider{
			httpClient: &http.Client{Timeout: 15 * time.Second},
			logger:     logger,
			token:      token,
			recordIDs:  map[string]string{},
		}, nil
	})
}

func (p *cloudflareProvider) Present(ctx context.Context, fqdn string, value string, ttl int) error {
	zone, err := p.lookupZoneForName(ctx, fqdn)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"type":    "TXT",
		"name":    strings.TrimSuffix(fqdn, "."),
		"content": value,
		"ttl":     ttl,
	}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, zone.ID)
	respBody, err := p.doJSONRequest(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	var envelope cloudflareEnvelope[cfDNSRecord]
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("cloudflare create challenge record decode failed")
	}
	if !envelope.Success || envelope.Result.ID == "" {
		return fmt.Errorf("cloudflare create challenge record failed")
	}

	p.mu.Lock()
	p.recordIDs[challengeRecordKey(fqdn, value)] = envelope.Result.ID
	p.mu.Unlock()
	return nil
}

func (p *cloudflareProvider) Cleanup(ctx context.Context, fqdn string, value string) error {
	zone, err := p.lookupZoneForName(ctx, fqdn)
	if err != nil {
		return err
	}

	recordID := ""
	key := challengeRecordKey(fqdn, value)
	p.mu.Lock()
	recordID = p.recordIDs[key]
	delete(p.recordIDs, key)
	p.mu.Unlock()

	if recordID == "" {
		recordID, err = p.lookupTXTRecordID(ctx, zone.ID, fqdn, value)
		if err != nil {
			return err
		}
		if recordID == "" {
			return nil
		}
	}

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, zone.ID, recordID)
	_, err = p.doJSONRequest(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	return nil
}

func (p *cloudflareProvider) lookupTXTRecordID(ctx context.Context, zoneID string, fqdn string, value string) (string, error) {
	query := url.Values{}
	query.Set("type", "TXT")
	query.Set("name", strings.TrimSuffix(fqdn, "."))
	query.Set("content", value)
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?%s", cloudflareAPIBase, zoneID, query.Encode())
	body, err := p.doJSONRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	var envelope cloudflareEnvelope[[]cfDNSRecord]
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("cloudflare lookup challenge record decode failed")
	}
	if !envelope.Success {
		return "", fmt.Errorf("cloudflare lookup challenge record failed")
	}
	if len(envelope.Result) == 0 {
		return "", nil
	}
	return envelope.Result[0].ID, nil
}

func (p *cloudflareProvider) lookupZoneForName(ctx context.Context, fqdn string) (cfZone, error) {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	parts := strings.Split(name, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		query := url.Values{}
		query.Set("name", candidate)
		endpoint := fmt.Sprintf("%s/zones?%s", cloudflareAPIBase, query.Encode())
		body, err := p.doJSONRequest(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		var envelope cloudflareEnvelope[[]cfZone]
		if err := json.Unmarshal(body, &envelope); err != nil {
			continue
		}
		if envelope.Success && len(envelope.Result) > 0 {
			return envelope.Result[0], nil
		}
	}
	return cfZone{}, fmt.Errorf("cloudflare zone lookup failed for challenge name")
}

func (p *cloudflareProvider) doJSONRequest(ctx context.Context, method string, endpoint string, body []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+p.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := p.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < 2 {
				cloudflareRetrySleep(time.Duration(attempt+1) * 200 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("cloudflare request failed")
		}
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("cloudflare response read failed")
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("cloudflare transient status %d", resp.StatusCode)
			if attempt < 2 {
				cloudflareRetrySleep(time.Duration(attempt+1) * 200 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("cloudflare request failed after retries")
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("cloudflare request failed with status %d", resp.StatusCode)
		}
		return respBody, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("cloudflare request failed")
}

func challengeRecordKey(fqdn string, value string) string {
	return strings.TrimSuffix(fqdn, ".") + "|" + value
}
