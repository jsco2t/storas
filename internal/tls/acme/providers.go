package acme

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	providerRegistryMu sync.RWMutex
	providerRegistry   = map[string]ProviderFactory{}
)

func RegisterProvider(name string, factory ProviderFactory) {
	providerRegistryMu.Lock()
	defer providerRegistryMu.Unlock()
	providerRegistry[strings.ToLower(strings.TrimSpace(name))] = factory
}

func LookupProvider(name string) (ProviderFactory, bool) {
	providerRegistryMu.RLock()
	defer providerRegistryMu.RUnlock()
	factory, ok := providerRegistry[strings.ToLower(strings.TrimSpace(name))]
	return factory, ok
}

func ProviderNames() []string {
	providerRegistryMu.RLock()
	defer providerRegistryMu.RUnlock()
	names := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func LoadCredentialsFromEnv(prefix string, keys []string) (map[string]string, error) {
	cleanPrefix := strings.TrimSpace(prefix)
	if cleanPrefix == "" {
		return nil, fmt.Errorf("acme credentials env_prefix is required")
	}
	creds := make(map[string]string, len(keys))
	for _, key := range keys {
		envName := cleanPrefix + key
		value := strings.TrimSpace(getenv(envName))
		if value == "" {
			return nil, fmt.Errorf("acme provider credential %s is required", envName)
		}
		creds[key] = value
	}
	return creds, nil
}

var getenv = os.Getenv
