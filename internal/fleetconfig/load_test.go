package fleetconfig

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/secretprovider"
)

type testProviderCatalog struct {
	kinds map[string]string
}

type testReference struct {
	kind      string
	canonical string
}

func (r testReference) ProviderKind() string { return r.kind }
func (r testReference) Canonical() string    { return r.canonical }

func (c testProviderCatalog) Parse(name, raw string) (secretprovider.Reference, error) {
	kind, ok := c.kinds[name]
	if !ok || raw == "" || strings.Contains(raw, "bad") || strings.Contains(raw, "$(") || strings.Contains(raw, "`") {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return testReference{kind: kind, canonical: "canonical/" + raw}, nil
}

func testOptions() LoadOptions {
	return LoadOptions{Providers: testProviderCatalog{kinds: map[string]string{
		"aws-production": secretprovider.KindAWSSecretsManager,
		"bao-production": secretprovider.KindOpenBaoKV2,
	}}}
}

func TestValidateManifestCanonicalizesTransportInput(t *testing.T) {
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Manager:       "platform-fleet",
		Agents: []Agent{{
			Name: "worker", SPIFFEID: "spiffe://cluster.example/ns/agents/sa/worker", Role: "no-access",
		}},
		Vaults: []Vault{{
			Name:   "automation",
			Grants: []Grant{{Agent: "worker", Role: "proxy"}},
			Credentials: []Credential{{
				Name: "TOKEN", Mode: "reference", Source: "aws-production",
				Reference: "application/token", RefreshInterval: "60s", MaxStaleness: "5m",
				ProviderKind: "client-supplied-kind-is-not-trusted",
			}},
		}}}
	canonical, err := ValidateManifest(manifest, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	credential := canonical.Vaults[0].Credentials[0]
	if credential.Reference != "canonical/application/token" || credential.ProviderKind != secretprovider.KindAWSSecretsManager {
		t.Fatalf("credential was not canonicalized: %#v", credential)
	}
	if _, err := ValidateManifest(Manifest{SchemaVersion: SchemaVersion, Manager: "platform-fleet", Agents: []Agent{{
		Name: "bad", SPIFFEID: "not-a-spiffe-id", Role: "no-access",
	}}}, testOptions()); err == nil {
		t.Fatal("invalid transport manifest was accepted")
	}
}

func TestValidateManifestPreservesOAuth2ClientCredentialsAuth(t *testing.T) {
	want := Auth{
		Kind:            "oauth2-client-credentials",
		ClientID:        "BLOCKS_CLIENT_ID",
		ClientSecret:    "BLOCKS_CLIENT_SECRET",
		TokenURL:        "https://auth.example.com/oauth2/token",
		Scopes:          []string{"blocks:read", "blocks:write", "blocks:delete"},
		Audience:        "infra-blocks-api",
		TokenAuthMethod: "client_secret_basic",
		Headers: map[string]string{
			"CF-Access-Client-Id":     "{{ CF_ACCESS_CLIENT_ID }}",
			"CF-Access-Client-Secret": "{{ CF_ACCESS_CLIENT_SECRET }}",
		},
	}
	credential := func(name string) Credential {
		return Credential{
			Name: name, Mode: "reference", Source: "aws-production", Reference: "approval/" + name,
			RefreshInterval: "5m", MaxStaleness: "1h",
		}
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Manager:       "platform-fleet",
		Vaults: []Vault{{
			Name: "approval",
			Services: []Service{{
				Name: "blocks", Host: "blocks.example.com", Path: "/blocks*", Auth: want,
			}},
			Credentials: []Credential{
				credential("BLOCKS_CLIENT_ID"), credential("BLOCKS_CLIENT_SECRET"),
				credential("CF_ACCESS_CLIENT_ID"), credential("CF_ACCESS_CLIENT_SECRET"),
			},
		}},
	}

	canonical, err := ValidateManifest(manifest, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := canonical.Vaults[0].Services[0].Auth; !reflect.DeepEqual(got, want) {
		t.Fatalf("OAuth auth changed during transport validation: got %#v, want %#v", got, want)
	}
}

func TestImportProvidersAreValidatedSeparatelyFromDurableProviders(t *testing.T) {
	path := writeManifest(t, "separate-providers.toml", `
schema_version = 1
manager = "platform-fleet"

[[vaults]]
name = "automation"

[[vaults.credentials]]
name = "LIVE_TOKEN"
mode = "reference"
source = "server-aws"
ref = "live/token"
refresh_interval = "1m"
max_staleness = "5m"

[[vaults.imports]]
name = "IMPORTED_TOKEN"
source = "cli-aws"
ref = "one-time/token"
`)
	manifest, err := LoadFiles([]string{path}, LoadOptions{
		Providers: testProviderCatalog{kinds: map[string]string{
			"server-aws": secretprovider.KindAWSSecretsManager,
		}},
		ImportProviders: testProviderCatalog{kinds: map[string]string{
			"cli-aws": secretprovider.KindAWSSecretsManager,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Vaults[0].Credentials[0].Reference != "canonical/live/token" ||
		manifest.Vaults[0].Imports[0].Reference != "canonical/one-time/token" {
		t.Fatalf("manifest = %#v", manifest)
	}
}

func TestLoadFilesRejectsMultipleStdinImports(t *testing.T) {
	path := writeManifest(t, "multiple-stdin.toml", `
schema_version = 1
manager = "platform-fleet"

[[vaults]]
name = "automation"

[[vaults.imports]]
name = "FIRST"
from = "stdin://"

[[vaults.imports]]
name = "SECOND"
from = "stdin://"
`)
	if _, err := LoadFiles([]string{path}, testOptions()); err == nil || !strings.Contains(err.Error(), "stdin import may be declared only once") {
		t.Fatalf("multiple stdin imports error = %v", err)
	}
}

func writeManifest(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validManifest = `
schema_version = 1
manager = "platform-fleet"

[[vaults]]
name = "github-automation"

[[vaults.agents]]
name = "pr-reviewer"
spiffe_id = "spiffe://cluster.example/ns/agents/sa/pr-reviewer"
role = "proxy"

[[vaults.services]]
name = "github-api"
host = "api.github.com/v1/*"
auth = { kind = "bearer", credential = "GITHUB_TOKEN" }

[[vaults.credentials]]
name = "GITHUB_TOKEN"
mode = "reference"
source = "aws-production"
ref = "application/github#token"
refresh_interval = "5m"
max_staleness = "1h"
`

func TestLoadFilesNormalizesAcceptedNestedSchema(t *testing.T) {
	path := writeManifest(t, "fleet.toml", validManifest)
	manifest, err := LoadFiles([]string{path}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || manifest.Manager != "platform-fleet" || len(manifest.Agents) != 1 || len(manifest.Vaults) != 1 {
		t.Fatalf("manifest = %#v", manifest)
	}
	agent := manifest.Agents[0]
	if agent.Name != "pr-reviewer" || agent.Role != "no-access" || agent.SPIFFEID != "spiffe://cluster.example/ns/agents/sa/pr-reviewer" {
		t.Fatalf("agent = %#v", agent)
	}
	vault := manifest.Vaults[0]
	if len(vault.Grants) != 1 || vault.Grants[0] != (Grant{Agent: "pr-reviewer", Role: "proxy"}) {
		t.Fatalf("grants = %#v", vault.Grants)
	}
	if service := vault.Services[0]; service.Host != "api.github.com" || service.Path != "/v1/*" {
		t.Fatalf("service = %#v", service)
	}
	credential := vault.Credentials[0]
	if credential.Reference != "canonical/application/github#token" || credential.ProviderKind != secretprovider.KindAWSSecretsManager {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestLoadFilesMergesAndSortsIndependentlyOfInputOrder(t *testing.T) {
	first := writeManifest(t, "01-base.toml", `
schema_version = 1
manager = "platform-fleet"
[[agents]]
name = "worker-agent"
spiffe_id = "spiffe://cluster.example/ns/agents/sa/worker"
[[vaults]]
name = "fleet-two"
[[vaults.grants]]
agent = "worker-agent"
role = "member"
[[vaults.imports]]
name = "Z_TOKEN"
from = "env://Z_TOKEN"
`)
	second := writeManifest(t, "02-extra.toml", `
schema_version = 1
manager = "platform-fleet"
[[vaults]]
name = "fleet-one"
[[vaults.agents]]
name = "other-agent"
spiffe_id = "spiffe://cluster.example/ns/agents/sa/other"
role = "proxy"
[[vaults.imports]]
name = "A_TOKEN"
from = "file:///run/secrets/a-token"
`)
	a, err := LoadFiles([]string{first, second}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadFiles([]string{second, first}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("merge depends on input order:\n%#v\n%#v", a, b)
	}
	if a.Agents[0].Name != "other-agent" || a.Vaults[0].Name != "fleet-one" {
		t.Fatalf("manifest is not canonical: %#v", a)
	}
}

func TestLoadFilesAllowsIdenticalDefinitionsAndRejectsConflicts(t *testing.T) {
	first := writeManifest(t, "a.toml", validManifest)
	equivalent := strings.Replace(validManifest, `refresh_interval = "5m"`, `refresh_interval = "300s"`, 1)
	equivalent = strings.Replace(equivalent, `max_staleness = "1h"`, `max_staleness = "60m"`, 1)
	equivalent = strings.Replace(equivalent, `auth = { kind = "bearer", credential = "GITHUB_TOKEN" }`, "enabled = true\nauth = { kind = \"bearer\", credential = \"GITHUB_TOKEN\" }", 1)
	duplicate := writeManifest(t, "b.toml", equivalent)
	if _, err := LoadFiles([]string{first, duplicate}, testOptions()); err != nil {
		t.Fatalf("identical definition: %v", err)
	}

	conflict := writeManifest(t, "c.toml", strings.Replace(validManifest, "api.github.com/v1/*", "uploads.github.com", 1))
	if _, err := LoadFiles([]string{first, conflict}, testOptions()); err == nil || !strings.Contains(err.Error(), "conflicting definitions") {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestLoadFilesRejectsUnknownAndInlineSecretFieldsWithoutEchoingValue(t *testing.T) {
	for _, field := range []string{"value", "token", "secret"} {
		body := validManifest + "\nvalue = \"ULTRA-SECRET-VALUE\"\n"
		if field != "value" {
			body = strings.Replace(body, "value =", field+" =", 1)
		}
		path := writeManifest(t, field+".toml", body)
		_, err := LoadFiles([]string{path}, testOptions())
		if err == nil || !strings.Contains(err.Error(), "unknown key") {
			t.Fatalf("%s error = %v", field, err)
		}
		if strings.Contains(err.Error(), "ULTRA-SECRET-VALUE") {
			t.Fatalf("secret leaked in error: %v", err)
		}
	}
}

func TestLoadFilesRejectsManagersAndDuplicateOwnership(t *testing.T) {
	first := writeManifest(t, "one.toml", validManifest)
	otherManager := writeManifest(t, "two.toml", strings.Replace(validManifest, "platform-fleet", "other-manager", 1))
	if _, err := LoadFiles([]string{first, otherManager}, testOptions()); err == nil || !strings.Contains(err.Error(), "one apply set") {
		t.Fatalf("manager error = %v", err)
	}

	dualMode := writeManifest(t, "dual.toml", validManifest+`
[[vaults.imports]]
name = "GITHUB_TOKEN"
from = "env://GITHUB_TOKEN"
`)
	if _, err := LoadFiles([]string{dualMode}, testOptions()); err == nil || !strings.Contains(err.Error(), "both an import and a reference") {
		t.Fatalf("ownership error = %v", err)
	}
}

func TestLoadFilesRejectsMalformedOrDuplicateSPIFFEIdentities(t *testing.T) {
	tests := []string{
		"spiffe://cluster.example/ns/agents/sa/*",
		"SPIFFE://cluster.example/ns/agents/sa/worker",
		"spiffe://cluster.example/ns/agents/sa/worker/../other",
		"not-a-spiffe-id",
	}
	for i, id := range tests {
		body := strings.Replace(validManifest, "spiffe://cluster.example/ns/agents/sa/pr-reviewer", id, 1)
		path := writeManifest(t, "bad-spiffe-"+string(rune('a'+i))+".toml", body)
		if _, err := LoadFiles([]string{path}, testOptions()); err == nil || !strings.Contains(err.Error(), "SPIFFE") {
			t.Fatalf("id %q error = %v", id, err)
		}
	}

	duplicate := writeManifest(t, "duplicate-spiffe.toml", validManifest+`
[[agents]]
name = "other-agent"
spiffe_id = "spiffe://cluster.example/ns/agents/sa/pr-reviewer"
`)
	if _, err := LoadFiles([]string{duplicate}, testOptions()); err == nil || !strings.Contains(err.Error(), "assigned to both") {
		t.Fatalf("duplicate SPIFFE error = %v", err)
	}
}

func TestLoadFilesRejectsInvalidProviderReferencesAndDurations(t *testing.T) {
	tests := map[string]string{
		"unknown provider": strings.Replace(validManifest, "aws-production", "missing-provider", 1),
		"bad reference":    strings.Replace(validManifest, "application/github#token", "bad-reference", 1),
		"inline reference": strings.Replace(validManifest, "application/github#token", "inline://secret-value", 1),
		"exec reference":   strings.Replace(validManifest, "application/github#token", "exec://resolver", 1),
		"short refresh":    strings.Replace(validManifest, `refresh_interval = "5m"`, `refresh_interval = "5s"`, 1),
		"fractional":       strings.Replace(validManifest, `refresh_interval = "5m"`, `refresh_interval = "10.5s"`, 1),
		"negative stale":   strings.Replace(validManifest, `max_staleness = "1h"`, `max_staleness = "-1s"`, 1),
		"inline mode":      strings.Replace(validManifest, `mode = "reference"`, `mode = "inline"`, 1),
	}
	for name, body := range tests {
		path := writeManifest(t, strings.ReplaceAll(name, " ", "-")+".toml", body)
		if _, err := LoadFiles([]string{path}, testOptions()); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	path := writeManifest(t, "no-registry.toml", validManifest)
	if _, err := LoadFiles([]string{path}, LoadOptions{}); err == nil || !strings.Contains(err.Error(), "provider reference") {
		t.Fatalf("missing registry error = %v", err)
	}
}

func TestLoadFilesRejectsUnsafeImportResolvers(t *testing.T) {
	unsafe := []string{
		"inline://secret", "literal://secret", "exec://program", "shell://program",
		"command://program", "env://TOKEN$(whoami)", "file:///tmp/`command`",
		"file://relative", "file:///run/../secret", "stdin://extra", "https://example.com/secret",
	}
	for i, source := range unsafe {
		body := `
schema_version = 1
manager = "platform-fleet"
[[vaults]]
name = "import-vault"
[[vaults.imports]]
name = "TOKEN"
from = "` + source + `"
`
		path := writeManifest(t, "unsafe-"+string(rune('a'+i))+".toml", body)
		if _, err := LoadFiles([]string{path}, testOptions()); err == nil || !strings.Contains(err.Error(), "invalid or unsafe") {
			t.Fatalf("source %q error = %v", source, err)
		}
	}
}

func TestLoadFilesAcceptsTypedImportsAndProviderImports(t *testing.T) {
	body := `
schema_version = 1
manager = "platform-fleet"
[[vaults]]
name = "import-vault"
[[vaults.imports]]
name = "ENV_TOKEN"
from = "env://TOKEN_NAME"
[[vaults.imports]]
name = "FILE_TOKEN"
from = "file:///run/secrets/token"
[[vaults.imports]]
name = "STDIN_TOKEN"
from = "stdin://"
[[vaults.imports]]
name = "PROVIDER_TOKEN"
source = "bao-production"
ref = "kv/application#token"
`
	path := writeManifest(t, "imports.toml", body)
	manifest, err := LoadFiles([]string{path}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	imports := manifest.Vaults[0].Imports
	if len(imports) != 4 || imports[2].Name != "PROVIDER_TOKEN" || imports[2].ProviderKind != secretprovider.KindOpenBaoKV2 {
		t.Fatalf("imports = %#v", imports)
	}
}

func TestLoadFilesRejectsMissingReferencesAndUndefinedGrants(t *testing.T) {
	missingCredential := writeManifest(t, "missing-credential.toml", strings.Replace(validManifest, "GITHUB_TOKEN\"\nmode", "OTHER_TOKEN\"\nmode", 1))
	if _, err := LoadFiles([]string{missingCredential}, testOptions()); err == nil || !strings.Contains(err.Error(), "undefined credential") {
		t.Fatalf("credential error = %v", err)
	}

	undefinedGrant := writeManifest(t, "undefined-agent.toml", `
schema_version = 1
manager = "platform-fleet"
[[vaults]]
name = "grant-vault"
[[vaults.grants]]
agent = "missing-agent"
role = "proxy"
`)
	if _, err := LoadFiles([]string{undefinedGrant}, testOptions()); err == nil || !strings.Contains(err.Error(), "undefined agent") {
		t.Fatalf("grant error = %v", err)
	}
}

func TestLoadFilesDoesNotReturnPartialStateOnAnyError(t *testing.T) {
	good := writeManifest(t, "good.toml", validManifest)
	bad := writeManifest(t, "bad.toml", "schema_version = 99\nmanager = \"platform-fleet\"\n")
	manifest, err := LoadFiles([]string{good, bad}, testOptions())
	if err == nil || manifest != nil {
		t.Fatalf("manifest = %#v, error = %v", manifest, err)
	}
}

func TestLoadFilesAcceptsOAuth2ClientCredentialsService(t *testing.T) {
	path := writeManifest(t, "oauth-client-credentials.toml", `
schema_version = 1
manager = "platform-fleet"
[[vaults]]
name = "approval"
[[vaults.services]]
name = "blocks"
host = "blocks.example.com/blocks*"
auth = { kind = "oauth2-client-credentials", client_id = "BLOCKS_CLIENT_ID", client_secret = "BLOCKS_CLIENT_SECRET", token_url = "https://auth.example.com/oauth2/token", scopes = ["blocks:read", "blocks:write", "blocks:delete"], audience = "infra-blocks-api", token_auth_method = "client_secret_basic", headers = { CF-Access-Client-Id = "{{ CF_ACCESS_CLIENT_ID }}", CF-Access-Client-Secret = "{{ CF_ACCESS_CLIENT_SECRET }}" } }
[[vaults.credentials]]
name = "BLOCKS_CLIENT_ID"
mode = "reference"
source = "aws-production"
ref = "blocks#client-id"
refresh_interval = "5m"
max_staleness = "1h"
[[vaults.credentials]]
name = "BLOCKS_CLIENT_SECRET"
mode = "reference"
source = "aws-production"
ref = "blocks#client-secret"
refresh_interval = "5m"
max_staleness = "1h"
[[vaults.credentials]]
name = "CF_ACCESS_CLIENT_ID"
mode = "reference"
source = "aws-production"
ref = "cloudflare#client-id"
refresh_interval = "5m"
max_staleness = "1h"
[[vaults.credentials]]
name = "CF_ACCESS_CLIENT_SECRET"
mode = "reference"
source = "aws-production"
ref = "cloudflare#client-secret"
refresh_interval = "5m"
max_staleness = "1h"
`)
	manifest, err := LoadFiles([]string{path}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	auth := manifest.Vaults[0].Services[0].Auth
	if auth.Kind != "oauth2-client-credentials" || auth.TokenURL != "https://auth.example.com/oauth2/token" || len(auth.Scopes) != 3 || auth.Audience != "infra-blocks-api" {
		t.Fatalf("OAuth client credentials auth drifted: %#v", auth)
	}
}

func TestLoadFilesReadAndPathErrors(t *testing.T) {
	if manifest, err := LoadFiles(nil, testOptions()); err == nil || manifest != nil {
		t.Fatalf("empty input = %#v, %v", manifest, err)
	}
	missing := filepath.Join(t.TempDir(), "missing.toml")
	if _, err := LoadFiles([]string{missing}, testOptions()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read error = %v", err)
	}
	path := writeManifest(t, "duplicate.toml", validManifest)
	if _, err := LoadFiles([]string{path, path}, testOptions()); err == nil {
		t.Fatal("duplicate path accepted")
	}
}
