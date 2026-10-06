package config

import (
	"strings"
	"testing"
)

func TestSubstrateProviderConfig(t *testing.T) {
	path := writeConfig(t, "substrate.toml", `schema_version = 1
[substrate_provider]
listen_address = ":50051"
server_cred_bundle = "/run/servicedns.podcert.ate.dev/credential-bundle.pem"
client_ca_file = "/run/podidentity.podcert.ate.dev/trust-bundle.pem"
`)
	res, err := Load(Options{Path: path, LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	got := res.Config.SubstrateProvider
	want := SubstrateProvider{
		ListenAddress:    ":50051",
		ServerCredBundle: "/run/servicedns.podcert.ate.dev/credential-bundle.pem",
		ClientCAFile:     "/run/podidentity.podcert.ate.dev/trust-bundle.pem",
	}
	if got != want {
		t.Fatalf("SubstrateProvider = %+v, want %+v", got, want)
	}
	if res.Sources["substrate_provider.listen_address"] != SourceTOML {
		t.Fatalf("listen_address source = %v", res.Sources["substrate_provider.listen_address"])
	}

	if d := Defaults().SubstrateProvider; d != (SubstrateProvider{}) {
		t.Fatalf("provider enabled by default: %+v", d)
	}
}

func TestSubstrateProviderValidation(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"missing files":   {`listen_address = ":50051"`, "substrate_provider.server_cred_bundle"},
		"relative bundle": {"listen_address = \":50051\"\nserver_cred_bundle = \"b.pem\"\nclient_ca_file = \"/ca.pem\"", "substrate_provider.server_cred_bundle"},
		"missing CA":      {"listen_address = \":50051\"\nserver_cred_bundle = \"/b.pem\"", "substrate_provider.client_ca_file"},
		"bad gateway":     {"listen_address = \":50051\"\nserver_cred_bundle = \"/b.pem\"\nclient_ca_file = \"/ca.pem\"\ngateway_identity = \"atenet\"", "substrate_provider.gateway_identity"},
		"bad listen":      {"listen_address = \"50051\"\nserver_cred_bundle = \"/b.pem\"\nclient_ca_file = \"/ca.pem\"", "substrate_provider.listen_address"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, "bad.toml", "schema_version=1\n[substrate_provider]\n"+tc.body+"\n")
			_, err := Load(Options{Path: path, LookupEnv: emptyEnv})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
