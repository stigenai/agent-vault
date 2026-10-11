package config

import "testing"

const githubAppConfigBase = `schema_version = 1
[server]
external_address = "https://agent-vault.example"
[auth]
mode = "spiffe"
workload_api = "unix:///run/spire/sockets/agent.sock"
trust_domains = ["spiffe://cluster.example"]
bootstrap_owner_ids = ["spiffe://cluster.example/owner"]

[[secret_providers]]
name = "onepassword"
kind = "onepassword-connect"
address = "https://onepassword-connect.example"
token = "file:///var/run/secrets/onepassword/connect-token"
`

func githubAppBlock(overrides string) string {
	return `
[[secret_providers]]
name = "axel"
kind = "github-app"
` + overrides
}

const githubAppValid = `app_id = "2954702"
installation_id = "112589902"
private_key_provider = "onepassword"
private_key_ref = "Personal Agents/nixfleet-axel/private_key"
`

func TestGitHubAppProviderTOML(t *testing.T) {
	path := writeConfig(t, "github-app.toml", githubAppConfigBase+githubAppBlock(githubAppValid+`api_url = "https://ghe.example/api/v3"`+"\n"))
	result, err := Load(Options{Path: path, LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	got := result.Config.SecretProviders[1]
	if got.Kind != "github-app" || got.AppID != "2954702" || got.InstallationID != "112589902" ||
		got.PrivateKeyProvider != "onepassword" || got.PrivateKeyRef != "Personal Agents/nixfleet-axel/private_key" ||
		got.APIURL != "https://ghe.example/api/v3" {
		t.Fatalf("provider = %#v", got)
	}
}

func TestGitHubAppProviderFailsClosed(t *testing.T) {
	cases := map[string]string{
		"missing app_id":        `installation_id = "1"` + "\n" + `private_key_provider = "onepassword"` + "\n" + `private_key_ref = "a/b/c"`,
		"missing installation":  `app_id = "1"` + "\n" + `private_key_provider = "onepassword"` + "\n" + `private_key_ref = "a/b/c"`,
		"non-numeric install":   `app_id = "1"` + "\n" + `installation_id = "abc"` + "\n" + `private_key_provider = "onepassword"` + "\n" + `private_key_ref = "a/b/c"`,
		"missing key provider":  `app_id = "1"` + "\n" + `installation_id = "1"` + "\n" + `private_key_ref = "a/b/c"`,
		"missing key ref":       `app_id = "1"` + "\n" + `installation_id = "1"` + "\n" + `private_key_provider = "onepassword"`,
		"unknown key provider":  `app_id = "1"` + "\n" + `installation_id = "1"` + "\n" + `private_key_provider = "nope"` + "\n" + `private_key_ref = "a/b/c"`,
		"self as key provider":  `app_id = "1"` + "\n" + `installation_id = "1"` + "\n" + `private_key_provider = "axel"` + "\n" + `private_key_ref = "a/b/c"`,
		"http api_url":          githubAppValid + `api_url = "http://api.github.com"`,
		"api_url with userinfo": githubAppValid + `api_url = "https://u:p@api.github.com"`,
		"padded key ref":        `app_id = "1"` + "\n" + `installation_id = "1"` + "\n" + `private_key_provider = "onepassword"` + "\n" + `private_key_ref = " a/b/c"`,
	}
	for name, body := range cases {
		path := writeConfig(t, "bad-github-app.toml", githubAppConfigBase+githubAppBlock(body))
		if _, err := Load(Options{Path: path, LookupEnv: emptyEnv}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// A github-app provider may not chain through another github-app provider.
	chained := githubAppConfigBase + githubAppBlock(githubAppValid) + `
[[secret_providers]]
name = "second"
kind = "github-app"
app_id = "1"
installation_id = "1"
private_key_provider = "axel"
private_key_ref = "token"
`
	if _, err := Load(Options{Path: writeConfig(t, "chain.toml", chained), LookupEnv: emptyEnv}); err == nil {
		t.Error("github-app chained through github-app accepted")
	}
}

func TestGitHubAppKeyProviderMayBeDeclaredAfter(t *testing.T) {
	// Order independent: github-app first, key provider afterwards.
	body := githubAppConfigBase[:len(githubAppConfigBase)-len(`
[[secret_providers]]
name = "onepassword"
kind = "onepassword-connect"
address = "https://onepassword-connect.example"
token = "file:///var/run/secrets/onepassword/connect-token"
`)] + githubAppBlock(githubAppValid) + `
[[secret_providers]]
name = "onepassword"
kind = "onepassword-connect"
address = "https://onepassword-connect.example"
token = "file:///var/run/secrets/onepassword/connect-token"
`
	if _, err := Load(Options{Path: writeConfig(t, "order.toml", body), LookupEnv: emptyEnv}); err != nil {
		t.Fatal(err)
	}
}
