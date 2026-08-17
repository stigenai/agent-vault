package config

import (
	"path/filepath"
	"testing"
)

func TestLoadClientDoesNotResolveServerSecrets(t *testing.T) {
	path := writeConfig(t, "client.toml", `schema_version = 1
[database]
url = "file:///not-mounted/database-url"
[encryption]
legacy_master_password = "file:///not-mounted/master-password"
[client]
address = "https://agent-vault.example"
vault = "production"
workload_api = "unix:///run/spire/sockets/agent.sock"
trust_domains = ["spiffe://cluster.example"]
`)
	client, err := LoadClient(ClientOptions{Path: path, LookupEnv: mapEnv(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if client.Address != "https://agent-vault.example" || client.Vault != "production" || client.WorkloadAPI != "unix:///run/spire/sockets/agent.sock" {
		t.Fatalf("client = %+v", client)
	}
}

func TestLoadClientEnvironmentPrecedence(t *testing.T) {
	path := writeConfig(t, "client.toml", `schema_version = 1
[client]
address = "https://toml.example"
workload_api = "unix:///toml/spire.sock"
trust_domains = ["spiffe://toml.example"]
`)
	client, err := LoadClient(ClientOptions{Path: path, LookupEnv: mapEnv(map[string]string{
		"AGENT_VAULT_ADDR":                 "https://env.example",
		"AGENT_VAULT_VAULT":                "env-vault",
		"SPIFFE_ENDPOINT_SOCKET":           "unix:///env/spire.sock",
		"AGENT_VAULT_SPIFFE_TRUST_DOMAINS": "spiffe://env.example",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if client.Address != "https://env.example" || client.Vault != "env-vault" || client.WorkloadAPI != "unix:///env/spire.sock" || len(client.TrustDomains) != 1 || client.TrustDomains[0] != "spiffe://env.example" {
		t.Fatalf("client = %+v", client)
	}
}

func TestLoadClientValidation(t *testing.T) {
	tests := []struct {
		name, address, socket, domains string
	}{
		{"requires HTTPS", "http://vault.example", "unix:///spire.sock", "spiffe://cluster.example"},
		{"absolute socket", "https://vault.example", "tcp://spire", "spiffe://cluster.example"},
		{"trust domain required", "https://vault.example", "unix:///spire.sock", ""},
		{"canonical trust domain", "https://vault.example", "unix:///spire.sock", "https://cluster.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadClient(ClientOptions{
				DefaultPath: filepath.Join(t.TempDir(), "missing"),
				LookupEnv: mapEnv(map[string]string{
					"AGENT_VAULT_ADDR":                 tc.address,
					"SPIFFE_ENDPOINT_SOCKET":           tc.socket,
					"AGENT_VAULT_SPIFFE_TRUST_DOMAINS": tc.domains,
				}),
			})
			if err == nil {
				t.Fatal("invalid client configuration was accepted")
			}
		})
	}
}
