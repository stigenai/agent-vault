package config

import (
	"path/filepath"
	"testing"
)

func TestLoadRelayUsesTOMLAndEnvironmentWithoutResolvingSecrets(t *testing.T) {
	path := writeConfig(t, "relay.toml", `schema_version = 1
[client]
address = "https://vault.example"
workload_api = "unix:///run/spire/agent.sock"
trust_domains = ["spiffe://cluster.example"]
[relay]
listen_address = "127.0.0.1:15000"
remote_address = "vault-proxy.example:443"
[database]
url = "file:///must-not-be-read"
`)
	cfg, err := LoadRelay(ClientOptions{
		Path: path,
		LookupEnv: mapEnv(map[string]string{
			"AGENT_VAULT_RELAY_LISTEN": "127.0.0.1:16000",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.ListenAddress != "127.0.0.1:16000" || cfg.Relay.RemoteAddress != "vault-proxy.example:443" {
		t.Fatalf("relay config = %#v", cfg.Relay)
	}
	if cfg.Client.WorkloadAPI != "unix:///run/spire/agent.sock" {
		t.Fatalf("workload API = %q", cfg.Client.WorkloadAPI)
	}
	if err := ValidateRelay(cfg.Relay); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRelay(ClientOptions{Path: filepath.Join(t.TempDir(), "missing.toml")}); err == nil {
		t.Fatal("explicit missing relay config was accepted")
	}
}

func TestValidateRelayFailsClosed(t *testing.T) {
	for _, relay := range []Relay{
		{ListenAddress: "0.0.0.0:14322", RemoteAddress: "proxy.example:443"},
		{ListenAddress: "127.0.0.1:14322"},
		{ListenAddress: "127.0.0.1:14322", RemoteAddress: "https://proxy.example"},
	} {
		if err := ValidateRelay(relay); err == nil {
			t.Fatalf("invalid relay accepted: %#v", relay)
		}
	}
}
