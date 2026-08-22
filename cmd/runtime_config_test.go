package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
)

func TestRuntimeConfigValidateIsCIUsable(t *testing.T) {
	path := writeRuntimeConfigFile(t, `schema_version=1
[server]
port=24321
`)
	output, err := executeCommand("config", "validate", "--config", path, "--quiet")
	if err != nil {
		t.Fatal(err)
	}
	if output != "" {
		t.Fatalf("quiet output = %q", output)
	}

	bad := writeRuntimeConfigFile(t, "schema_version=1\nunknown=true\n")
	if _, err := executeCommand("config", "validate", "--config", bad, "--quiet"); err == nil {
		t.Fatal("invalid config returned successful exit status")
	}
}

func TestRuntimeConfigInspectReportsSourcesAndRedactsSecrets(t *testing.T) {
	secret := "postgres://inspect-user:never-print-this@example/db"
	path := writeRuntimeConfigFile(t, `schema_version=1
[server]
port=24321
[database]
url="env://INSPECT_DATABASE_URL"
`)
	t.Setenv("INSPECT_DATABASE_URL", secret)
	t.Setenv("AGENT_VAULT_HOST", "environment-host")
	t.Setenv("AGENT_VAULT_VAULT", "environment-vault")

	output, err := executeCommand(
		"config", "inspect", "--config", path, "--host", "flag-host", "--format", "json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, secret) || strings.Contains(output, "never-print-this") {
		t.Fatalf("inspection leaked secret: %s", output)
	}
	var payload struct {
		Path   string                         `json:"path"`
		Fields []runtimeconfig.InspectedField `json:"fields"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatal(err)
	}
	fields := make(map[string]runtimeconfig.InspectedField, len(payload.Fields))
	for _, field := range payload.Fields {
		fields[field.Name] = field
	}
	assertInspectedField(t, fields, "server.host", "flag-host", runtimeconfig.SourceFlag)
	assertInspectedField(t, fields, "server.port", float64(24321), runtimeconfig.SourceTOML)
	assertInspectedField(t, fields, "database.url", "env://INSPECT_DATABASE_URL", runtimeconfig.SourceTOML)
	assertInspectedField(t, fields, "client.vault", "environment-vault", runtimeconfig.SourceEnvironment)
	assertInspectedField(t, fields, "smtp.port", float64(587), runtimeconfig.SourceDefault)
	if _, ok := os.LookupEnv("INSPECT_DATABASE_URL"); ok {
		t.Fatal("resolved referenced environment secret was not cleared")
	}
}

func assertInspectedField(t *testing.T, fields map[string]runtimeconfig.InspectedField, name string, value interface{}, source runtimeconfig.Source) {
	t.Helper()
	field, ok := fields[name]
	if !ok {
		t.Fatalf("missing field %s", name)
	}
	if field.Value != value || field.Source != source {
		t.Fatalf("%s = %#v/%q, want %#v/%q", name, field.Value, field.Source, value, source)
	}
}

func writeRuntimeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
