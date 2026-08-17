package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type RelayClient struct {
	Client Client
	Relay  Relay
}

// FleetClient is the least-privilege CLI configuration needed for direct
// fleet imports. It deliberately excludes database, SMTP, encryption, and
// other server-side secret references.
type FleetClient struct {
	Client          Client
	SecretProviders []SecretProviderConfig
}

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

// LoadFleetClient loads client connectivity plus one-time import providers
// without resolving unrelated server configuration or secret references.
func LoadFleetClient(opts ClientOptions) (FleetClient, error) {
	client, err := LoadClient(opts)
	if err != nil {
		return FleetClient{}, err
	}
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	result := FleetClient{Client: client}
	path, required := discoverPath(Options{Path: opts.Path, DefaultPath: opts.DefaultPath}, lookup)
	if path == "" {
		return result, nil
	}
	partial, err := decodeFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return result, nil
		}
		return FleetClient{}, fmt.Errorf("fleet client config %q: %w", path, err)
	}
	if partial.SecretProviders != nil {
		result.SecretProviders = append([]SecretProviderConfig(nil), (*partial.SecretProviders)...)
	}
	auth := Auth{
		Mode: "spiffe", WorkloadAPI: client.WorkloadAPI,
		TrustDomains: append([]string(nil), client.TrustDomains...),
	}
	if client.WorkloadAPI == "" {
		auth.Mode = "legacy"
	}
	if err := validateSecretProviders(result.SecretProviders, auth); err != nil {
		return FleetClient{}, fmt.Errorf("invalid fleet client configuration: %w", err)
	}
	return result, nil
}

// LoadRelay reads only the public client and relay sections. It deliberately
// avoids resolving database, encryption, SMTP, or provider secrets.
func LoadRelay(opts ClientOptions) (RelayClient, error) {
	client, err := LoadClient(opts)
	if err != nil {
		return RelayClient{}, err
	}
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	result := RelayClient{Client: client, Relay: Relay{
		ListenAddress: "127.0.0.1:14322",
		ListenerMode:  "loopback",
	}}
	path, required := discoverPath(Options{Path: opts.Path, DefaultPath: opts.DefaultPath}, lookup)
	if path != "" {
		partial, err := decodeFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) || required {
				return RelayClient{}, fmt.Errorf("relay config %q: %w", path, err)
			}
		} else {
			if partial.Relay.ListenAddress != nil {
				result.Relay.ListenAddress = *partial.Relay.ListenAddress
			}
			if partial.Relay.RemoteAddress != nil {
				result.Relay.RemoteAddress = *partial.Relay.RemoteAddress
			}
			if partial.Relay.ListenerMode != nil {
				result.Relay.ListenerMode = *partial.Relay.ListenerMode
			}
		}
	}
	if value, ok := lookup("AGENT_VAULT_RELAY_LISTEN"); ok && strings.TrimSpace(value) != "" {
		result.Relay.ListenAddress = value
	}
	if value, ok := lookup("AGENT_VAULT_RELAY_REMOTE"); ok && strings.TrimSpace(value) != "" {
		result.Relay.RemoteAddress = value
	}
	if value, ok := lookup("AGENT_VAULT_RELAY_LISTENER_MODE"); ok && strings.TrimSpace(value) != "" {
		result.Relay.ListenerMode = value
	}
	return result, nil
}

func ValidateRelay(relay Relay) error {
	host, listenPort, err := net.SplitHostPort(relay.ListenAddress)
	if err != nil {
		return fmt.Errorf("relay.listen_address: expected host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("relay.listen_address: must use an explicit IP address")
	}
	switch relay.ListenerMode {
	case "loopback":
		if !ip.IsLoopback() {
			return fmt.Errorf("relay.listen_address: listener_mode loopback requires a loopback IP")
		}
	case "network":
		if ip.IsLoopback() {
			return fmt.Errorf("relay.listen_address: listener_mode network requires a non-loopback IP")
		}
	default:
		return fmt.Errorf("relay.listener_mode: expected loopback or network")
	}
	if port, err := strconv.Atoi(listenPort); err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("relay.listen_address: invalid port")
	}
	if strings.TrimSpace(relay.RemoteAddress) == "" {
		return fmt.Errorf("relay.remote_address: is required")
	}
	remoteHost, remotePort, err := net.SplitHostPort(relay.RemoteAddress)
	if err != nil || strings.TrimSpace(remoteHost) == "" {
		return fmt.Errorf("relay.remote_address: expected host:port")
	}
	if port, err := strconv.Atoi(remotePort); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("relay.remote_address: invalid port")
	}
	return nil
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
