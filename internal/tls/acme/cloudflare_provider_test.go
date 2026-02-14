package acme

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCloudflareProviderPresentAndCleanupMapping(t *testing.T) {
	var postBody map[string]any
	deleteCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones") && r.URL.Query().Get("name") == "example.com":
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":[{"id":"zone-1","name":"example.com"}]}`)
			return
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			if err := json.NewDecoder(r.Body).Decode(&postBody); err != nil {
				t.Fatalf("decode post body: %v", err)
			}
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"id":"record-1"}}`)
			return
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-1/dns_records/record-1":
			deleteCalled = true
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)
			return
		}
		http.Error(w, "unexpected route", http.StatusNotFound)
	}))
	defer server.Close()

	origBase := cloudflareAPIBase
	origSleep := cloudflareRetrySleep
	cloudflareAPIBase = server.URL
	cloudflareRetrySleep = func(_ time.Duration) {}
	t.Cleanup(func() {
		cloudflareAPIBase = origBase
		cloudflareRetrySleep = origSleep
	})

	factory, ok := LookupProvider("cloudflare")
	if !ok {
		t.Fatal("expected cloudflare provider")
	}
	provider, err := factory(ProviderConfig{Credentials: map[string]string{"API_TOKEN": "token"}})
	if err != nil {
		t.Fatalf("provider create error: %v", err)
	}
	cf := provider.(*cloudflareProvider)
	cf.httpClient = server.Client()

	if err := cf.Present(context.Background(), "_acme-challenge.storage.example.com.", "challenge-value", 60); err != nil {
		t.Fatalf("Present error: %v", err)
	}
	if postBody["type"] != "TXT" {
		t.Fatalf("expected TXT record type, got %#v", postBody["type"])
	}
	if postBody["name"] != "_acme-challenge.storage.example.com" {
		t.Fatalf("unexpected challenge name: %#v", postBody["name"])
	}
	if postBody["content"] != "challenge-value" {
		t.Fatalf("unexpected challenge content: %#v", postBody["content"])
	}

	if err := cf.Cleanup(context.Background(), "_acme-challenge.storage.example.com.", "challenge-value"); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}
	if !deleteCalled {
		t.Fatal("expected DNS record delete call")
	}
}

func TestCloudflareProviderPresentRetriesTransientFailures(t *testing.T) {
	postAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":[{"id":"zone-1","name":"example.com"}]}`)
			return
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			postAttempts++
			if postAttempts == 1 {
				http.Error(w, "temporary", http.StatusBadGateway)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"id":"record-1"}}`)
			return
		}
		http.Error(w, "unexpected", http.StatusNotFound)
	}))
	defer server.Close()

	origBase := cloudflareAPIBase
	origSleep := cloudflareRetrySleep
	cloudflareAPIBase = server.URL
	cloudflareRetrySleep = func(_ time.Duration) {}
	t.Cleanup(func() {
		cloudflareAPIBase = origBase
		cloudflareRetrySleep = origSleep
	})

	factory, ok := LookupProvider("cloudflare")
	if !ok {
		t.Fatal("expected cloudflare provider")
	}
	provider, err := factory(ProviderConfig{Credentials: map[string]string{"API_TOKEN": "token"}})
	if err != nil {
		t.Fatalf("provider create error: %v", err)
	}
	cf := provider.(*cloudflareProvider)
	cf.httpClient = server.Client()

	if err := cf.Present(context.Background(), "_acme-challenge.storage.example.com.", "challenge-value", 60); err != nil {
		t.Fatalf("Present error: %v", err)
	}
	if postAttempts != 2 {
		t.Fatalf("expected retry attempt count=2, got %d", postAttempts)
	}
}
