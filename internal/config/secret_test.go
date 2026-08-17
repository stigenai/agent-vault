package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSecretRef(t *testing.T) {
	tests := []struct {
		name, raw, want string
	}{
		{"environment", "env://DATABASE_URL", "env://DATABASE_URL"},
		{"file", "file:///var/run/secrets/database-url", "file:///var/run/secrets/database-url"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecretRef(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Fatalf("String() = %q, want %q", got.String(), tc.want)
			}
		})
	}
}

func TestParseSecretRefRejectsUnsafeInputsWithoutEchoingLiterals(t *testing.T) {
	literal := "postgres://admin:do-not-echo@example/db"
	tests := []string{
		literal,
		"exec://print-secret",
		"env://BAD-NAME",
		"env://",
		"file://relative/path",
		"file:///tmp/../secret",
		"file://",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseSecretRef(raw)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), literal) {
				t.Fatalf("error leaked literal: %v", err)
			}
		})
	}
}

func TestResolveEnvironmentSecret(t *testing.T) {
	ref := mustSecretRef("env://TEST_SECRET")
	value, err := (Resolver{LookupEnv: mapEnv(map[string]string{"TEST_SECRET": "sensitive-value"})}).Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if value.RevealString() != "sensitive-value" {
		t.Fatal("resolved wrong value")
	}
	if value.String() != "env://TEST_SECRET" {
		t.Fatalf("String() = %q", value.String())
	}

	copyBytes := value.Bytes()
	copyBytes[0] = 'X'
	if value.RevealString() != "sensitive-value" {
		t.Fatal("Bytes returned backing storage")
	}
	value.Wipe()
	if value.IsSet() || value.RevealString() != "" {
		t.Fatal("Wipe did not clear value")
	}
}

func TestResolveEmptySecretIsStillSet(t *testing.T) {
	value, err := (Resolver{LookupEnv: mapEnv(map[string]string{"EMPTY_SECRET": ""})}).Resolve(mustSecretRef("env://EMPTY_SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	if !value.IsSet() {
		t.Fatal("empty but present secret reported unset")
	}
}

func TestResolveFileSecretIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := mustSecretRef("file://" + path)
	value, err := (Resolver{MaxBytes: 8}).Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if value.RevealString() != "12345678" {
		t.Fatal("wrong file value")
	}
	if _, err := (Resolver{MaxBytes: 7}).Resolve(ref); err == nil || !strings.Contains(err.Error(), "exceeds 7 bytes") {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestResolverErrorsNeverContainResolvedValues(t *testing.T) {
	secret := "never-print-this-secret"
	ref := mustSecretRef("file:///safe/path")
	_, err := (Resolver{ReadFile: func(string, int64) ([]byte, error) {
		return []byte(secret), errors.New("provider unavailable")
	}}).Resolve(ref)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", err)
	}

	envRef := mustSecretRef("env://LARGE_SECRET")
	_, err = (Resolver{LookupEnv: mapEnv(map[string]string{"LARGE_SECRET": secret}), MaxBytes: 3}).Resolve(envRef)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("oversize error leaked secret: %v", err)
	}
}

func TestSecretValueFormattingAndSerializationAreRedacted(t *testing.T) {
	secret := "super-secret-value"
	value := secretValue("env://SAFE_NAME", secret)
	outputs := []string{
		fmt.Sprint(value),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%#v", value),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(encoded))
	for _, output := range outputs {
		if strings.Contains(output, secret) {
			t.Fatalf("formatted output leaked secret: %s", output)
		}
		if !strings.Contains(output, "env://SAFE_NAME") {
			t.Fatalf("formatted output omitted safe reference: %s", output)
		}
	}
}

func TestInlineTOMLSecretsAreRejectedWithoutEcho(t *testing.T) {
	tests := []struct {
		name, section, field, secret string
	}{
		{"database URL", "database", "url", "postgres://admin:database-inline@example/db"},
		{"legacy master password", "encryption", "legacy_master_password", "master-inline-secret"},
		{"SMTP password", "smtp", "password", "smtp-inline-secret"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf("schema_version=1\n[%s]\n%s=%q\n", tc.section, tc.field, tc.secret)
			path := writeConfig(t, "inline.toml", body)
			_, err := Load(Options{Path: path, LookupEnv: emptyEnv})
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), tc.secret) || strings.Contains(err.Error(), "inline-secret") {
				t.Fatalf("error leaked inline value: %v", err)
			}
			if !strings.Contains(err.Error(), ErrSecretReferenceRequired.Error()) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestResolvedSecretsDoNotLeakThroughRuntimeFormattingOrValidation(t *testing.T) {
	secrets := []string{
		"postgres://admin:database-format-secret@example/db",
		"master-format-secret",
		"smtp-format-secret",
	}
	path := writeConfig(t, "safe.toml", `schema_version=1
[database]
url="env://SAFE_DATABASE_URL"
[encryption]
legacy_master_password="env://SAFE_MASTER_PASSWORD"
[smtp]
password="env://SAFE_SMTP_PASSWORD"
`)
	result, err := Load(Options{Path: path, LookupEnv: mapEnv(map[string]string{
		"SAFE_DATABASE_URL": secrets[0], "SAFE_MASTER_PASSWORD": secrets[1], "SAFE_SMTP_PASSWORD": secrets[2],
	})})
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{fmt.Sprint(result.Config), fmt.Sprintf("%+v", result.Config), fmt.Sprintf("%#v", result.Config)}
	encoded, err := json.Marshal(result.Config)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(encoded))
	for _, output := range outputs {
		for _, secret := range secrets {
			if strings.Contains(output, secret) || strings.Contains(output, "format-secret") {
				t.Fatalf("runtime formatting leaked secret: %s", output)
			}
		}
	}

	result.Config.Database.SQLitePath = "/tmp/conflicting.db"
	err = result.Config.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "format-secret") {
			t.Fatalf("validation error leaked secret: %v", err)
		}
	}
}
