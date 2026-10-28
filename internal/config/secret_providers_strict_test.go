package config

import (
	"strings"
	"testing"
)

func TestSecretProvidersGitHubAppAndSPIFFEJWTSVIDLoadStrict(t *testing.T) {
	const spiffeBlock = "\n[[secret_providers]]\nname = \"spire\"\nkind = \"spiffe-jwt-svid\"\n"
	const spiffeSocket = `workload_api = "unix:///spiffe-workload-api/spire-agent.sock"` + "\n"
	body := githubAppConfigBase + githubAppBlock(githubAppValid+`api_url = "https://ghe.example/api/v3"`+"\n") + spiffeBlock + spiffeSocket
	result, err := Load(Options{Path: writeConfig(t, "both.toml", body), LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	providers := result.Config.SecretProviders
	if len(providers) != 3 || providers[0].Kind != "onepassword-connect" {
		t.Fatalf("providers = %#v", providers)
	}
	app, svid := providers[1], providers[2]
	if app.Kind != "github-app" || app.AppID != "2954702" || app.InstallationID != "112589902" ||
		app.PrivateKeyProvider != "onepassword" || app.PrivateKeyRef != "Personal Agents/nixfleet-axel/private_key" ||
		app.APIURL != "https://ghe.example/api/v3" {
		t.Fatalf("github-app = %#v", app)
	}
	if svid.Name != "spire" || svid.Kind != "spiffe-jwt-svid" || svid.WorkloadAPI != "unix:///spiffe-workload-api/spire-agent.sock" {
		t.Fatalf("spiffe-jwt-svid = %#v", svid)
	}

	for name, bad := range map[string]struct{ body, want string }{
		"unknown github-app key":      {githubAppConfigBase + githubAppBlock(githubAppValid+"bogus = true\n") + spiffeBlock + spiffeSocket, "strict mode"},
		"unknown spiffe-jwt-svid key": {githubAppConfigBase + githubAppBlock(githubAppValid) + spiffeBlock + spiffeSocket + "bogus = true\n", "strict mode"},
		"non-unix workload_api":       {githubAppConfigBase + githubAppBlock(githubAppValid) + spiffeBlock + `workload_api = "tcp://x"` + "\n", "workload_api"},
	} {
		_, err := Load(Options{Path: writeConfig(t, "bad.toml", bad.body), LookupEnv: emptyEnv})
		if err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s: err = %v, want %q", name, err, bad.want)
		}
	}
}
