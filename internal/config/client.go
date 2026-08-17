package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ClientOptions controls the lightweight CLI configuration load. Unlike Load,
// it never resolves server-side secret references from the same TOML file.
type ClientOptions struct {
	Path        string
	DefaultPath string
	LookupEnv   LookupEnv
}

// LoadClient resolves the client subsection from defaults < TOML < environment.
// It is safe for operator pods that can read the shared fleet ConfigMap but
// must not read database, SMTP, or encryption secret volumes.
func LoadClient(opts ClientOptions) (Client, error) {
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	client := Defaults().Client
	path, required := discoverPath(Options{Path: opts.Path, DefaultPath: opts.DefaultPath}, lookup)
	if path != "" {
		partial, err := decodeFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) || required {
				return Client{}, fmt.Errorf("client config %q: %w", path, err)
			}
		} else {
			if partial.SchemaVersion == nil {
				return Client{}, fmt.Errorf("client config %q: schema_version is required", path)
			}
			if *partial.SchemaVersion != SchemaVersion {
				return Client{}, fmt.Errorf("client config %q: unsupported schema_version %d", path, *partial.SchemaVersion)
			}
			if partial.Client.Address != nil {
				client.Address = *partial.Client.Address
			}
			if partial.Client.Vault != nil {
				client.Vault = *partial.Client.Vault
			}
			if partial.Client.WorkloadAPI != nil {
				client.WorkloadAPI = *partial.Client.WorkloadAPI
			}
			if partial.Client.TrustDomains != nil {
				client.TrustDomains = append([]string(nil), (*partial.Client.TrustDomains)...)
			}
		}
	}
	if value, ok := lookup("AGENT_VAULT_ADDR"); ok && strings.TrimSpace(value) != "" {
		client.Address = value
	}
	if value, ok := lookup("AGENT_VAULT_VAULT"); ok && strings.TrimSpace(value) != "" {
		client.Vault = value
	}
	if value, ok := lookup("SPIFFE_ENDPOINT_SOCKET"); ok && strings.TrimSpace(value) != "" {
		client.WorkloadAPI = value
	}
	if value, ok := lookup("AGENT_VAULT_SPIFFE_TRUST_DOMAINS"); ok && strings.TrimSpace(value) != "" {
		client.TrustDomains = splitList(value)
	}
	if err := validateClient(client); err != nil {
		return Client{}, err
	}
	return client, nil
}

func validateClient(client Client) error {
	if err := validHTTPURL("client.address", client.Address, false); err != nil {
		return err
	}
	if client.WorkloadAPI == "" {
		if len(client.TrustDomains) > 0 {
			return fmt.Errorf("client.workload_api: required when trust_domains are configured")
		}
		return nil
	}
	if !strings.HasPrefix(client.WorkloadAPI, "unix:///") {
		return fmt.Errorf("client.workload_api: must be an absolute unix:// socket")
	}
	if !strings.HasPrefix(strings.ToLower(client.Address), "https://") {
		return fmt.Errorf("client.address: HTTPS is required with SPIFFE workload identity")
	}
	if len(client.TrustDomains) == 0 {
		return fmt.Errorf("client.trust_domains: at least one trust domain is required")
	}
	seen := make(map[string]struct{}, len(client.TrustDomains))
	for _, raw := range client.TrustDomains {
		domain, err := parseTrustDomain(raw)
		if err != nil {
			return fmt.Errorf("client.trust_domains: %q: %w", raw, err)
		}
		if _, ok := seen[domain.String()]; ok {
			return fmt.Errorf("client.trust_domains: duplicate %q", raw)
		}
		seen[domain.String()] = struct{}{}
	}
	return nil
}
