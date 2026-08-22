package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestInspectFieldsAreCompleteStableAndRedacted(t *testing.T) {
	cfg := Defaults()
	cfg.Database.URL = secretValue("env://DATABASE_SECRET", "postgres://user:inspect-secret@example/db")
	cfg.Encryption.LegacyMasterPassword = NewSecretValue([]byte("literal-inspect-secret"))
	result := Result{Config: cfg, Sources: defaultSources()}

	fields := result.InspectFields()
	if len(fields) != len(fieldNames)+1 {
		t.Fatalf("fields = %d, want %d", len(fields), len(fieldNames)+1)
	}
	for i, field := range fields[:len(fieldNames)] {
		if field.Name != fieldNames[i] {
			t.Fatalf("field %d = %q, want %q", i, field.Name, fieldNames[i])
		}
	}
	if fields[len(fields)-1].Name != "secret_providers" {
		t.Fatalf("last field = %q, want secret_providers", fields[len(fields)-1].Name)
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded) + fmt.Sprint(fields)
	if strings.Contains(output, "inspect-secret") {
		t.Fatalf("inspection leaked resolved value: %s", output)
	}
	if !strings.Contains(output, "env://DATABASE_SECRET") || !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("inspection omitted safe redaction metadata: %s", output)
	}
}
