package fleetconfig

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/secretprovider"
	"gopkg.in/yaml.v3"
)

func TestKubernetesFleetDesiredStateExamplesValidate(t *testing.T) {
	root := fleetRepositoryRoot(t)
	dir := filepath.Join(root, "examples", "kubernetes", "fleet", "desired-state")
	providers := testProviderCatalog{kinds: map[string]string{
		"aws-staging":            secretprovider.KindAWSSecretsManager,
		"aws-production":         secretprovider.KindAWSSecretsManager,
		"bao-production":         secretprovider.KindOpenBaoKV2,
		"onepassword-production": secretprovider.KindOnePassword,
	}}
	for _, environment := range []string{"staging.toml", "production.toml"} {
		t.Run(environment, func(t *testing.T) {
			manifest, err := LoadFiles([]string{
				filepath.Join(dir, "base.toml"), filepath.Join(dir, environment),
			}, LoadOptions{Providers: providers, ImportProviders: providers})
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Manager != "platform-fleet" || len(manifest.Agents) != 1 || len(manifest.Vaults) != 1 ||
				len(manifest.Vaults[0].Services) != 1 || len(manifest.Vaults[0].Credentials) != 1 {
				t.Fatalf("composed manifest = %#v", manifest)
			}
		})
	}
	imports, err := LoadFiles([]string{filepath.Join(dir, "imports.toml")}, LoadOptions{
		Providers: providers, ImportProviders: providers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(imports.Vaults) != 1 || len(imports.Vaults[0].Imports) != 6 {
		t.Fatalf("import example = %#v", imports)
	}

	reconciler, err := os.ReadFile(filepath.Join(root, "examples", "kubernetes", "fleet", "reconciler.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"serviceAccountName: agent-vault-reconciler", "concurrencyPolicy: Forbid",
		"AGENT_VAULT_CONFIG", "spire-agent-socket", "--yes", "base.toml", "environment.toml",
	} {
		if !strings.Contains(string(reconciler), required) {
			t.Errorf("reconciler example omits %q", required)
		}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(reconciler))
	documents := 0
	for {
		var document any
		if err := decoder.Decode(&document); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("parse reconciler YAML: %v", err)
		}
		documents++
	}
	if documents != 2 {
		t.Fatalf("reconciler YAML documents = %d, want 2", documents)
	}

	docBytes, err := os.ReadFile(filepath.Join(root, "docs", "guides", "fleet-reconciliation.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(docBytes)
	for _, required := range []string{
		"schema_version", "manager", "spiffe_id", "vaults.grants", "vaults.services",
		"vaults.credentials", "vaults.imports", "refresh_interval", "max_staleness",
		"--plan-sha256", "--adopt", "--prune", "--prune-credentials", "--refresh-import", "rollback",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("fleet schema reference omits %q", required)
		}
	}
}

func fleetRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
