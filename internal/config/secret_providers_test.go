package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecretProviderTOMLAndInspectionAreRedacted(t *testing.T) {
	path := writeConfig(t, "providers.toml", `schema_version = 1

[server]
external_address = "https://agent-vault.example"

[auth]
mode = "spiffe"
workload_api = "unix:///run/spire/sockets/agent.sock"
trust_domains = ["spiffe://cluster.example"]
bootstrap_owner_ids = ["spiffe://cluster.example/ns/platform/sa/owner"]

[[secret_providers]]
name = "aws-production"
kind = "aws-secrets-manager"
region = "us-east-1"

[[secret_providers]]
name = "bao-production"
kind = "openbao-kv-v2"
address = "https://openbao.example"
auth = "spiffe-x509"
auth_mount = "cert"
role = "agent-vault"

[[secret_providers]]
name = "onepassword-production"
kind = "onepassword-connect"
address = "https://onepassword-connect.example"
token = "file:///var/run/secrets/onepassword/connect-token"

[[secret_providers]]
name = "infisical-production"
kind = "infisical"
`)
	result, err := Load(Options{Path: path, LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Config.SecretProviders) != 4 || result.Config.SecretProviders[2].Token.String() != "file:///var/run/secrets/onepassword/connect-token" {
		t.Fatalf("providers = %#v", result.Config.SecretProviders)
	}
	encoded, err := json.Marshal(result.InspectFields())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "file:///var/run/secrets/onepassword/connect-token") || strings.Contains(string(encoded), "CONNECT-TOKEN-VALUE") {
		t.Fatalf("provider inspection = %s", encoded)
	}
}

func TestSecretProviderTOMLFailsClosed(t *testing.T) {
	base := `schema_version = 1
[server]
external_address = "https://agent-vault.example"
[auth]
mode = "spiffe"
workload_api = "unix:///run/spire/sockets/agent.sock"
trust_domains = ["spiffe://cluster.example"]
bootstrap_owner_ids = ["spiffe://cluster.example/owner"]
`
	tests := []string{
		`[[secret_providers]]
name = "AWS"
kind = "aws-secrets-manager"
region = "us-east-1"`,
		`[[secret_providers]]
name = "onepassword"
kind = "onepassword-connect"
address = "https://connect.example"
token = "INLINE-CONNECT-SECRET"`,
		`[[secret_providers]]
name = "bao"
kind = "openbao-kv-v2"
address = "https://bao.example"
auth = "spiffe-jwt"
role = "agent-vault"`,
		`[[secret_providers]]
name = "unknown"
kind = "shell"`,
	}
	for i, body := range tests {
		path := writeConfig(t, "invalid-provider.toml", base+body)
		if _, err := Load(Options{Path: path, LookupEnv: emptyEnv}); err == nil {
			t.Fatalf("invalid provider %d accepted", i)
		}
	}
}
