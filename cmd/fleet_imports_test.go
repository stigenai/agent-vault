package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

type fleetImportTestProviders struct {
	value []byte
	err   error
}

func (p fleetImportTestProviders) Parse(_, raw string) (secretprovider.Reference, error) {
	if p.err != nil {
		return nil, p.err
	}
	return remoteFleetReference{kind: secretprovider.KindAWSSecretsManager, canonical: raw}, nil
}

func (p fleetImportTestProviders) Fetch(context.Context, string, secretprovider.Reference) (secretprovider.Result, error) {
	if p.err != nil {
		return secretprovider.Result{}, p.err
	}
	return secretprovider.NewResult(p.value, "version")
}

func TestResolveFleetImportSupportsFileStdinAndProviderWithoutLeaking(t *testing.T) {
	fileValue := []byte("file-secret-value")
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, fileValue, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetIn(bytes.NewBufferString("stdin-secret-value"))

	tests := []struct {
		name      string
		item      fleetconfig.Import
		providers fleetImportProviders
		want      string
	}{
		{name: "file", item: fleetconfig.Import{Name: "TOKEN", From: "file://" + path}, want: "file-secret-value"},
		{name: "stdin", item: fleetconfig.Import{Name: "TOKEN", From: "stdin://"}, want: "stdin-secret-value"},
		{
			name:      "provider",
			item:      fleetconfig.Import{Name: "TOKEN", Source: "aws-production", Reference: "application/token"},
			providers: fleetImportTestProviders{value: []byte("provider-secret-value")},
			want:      "provider-secret-value",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := resolveFleetImport(cmd, test.providers, test.item)
			if err != nil {
				t.Fatal(err)
			}
			defer vaultcrypto.WipeBytes(value)
			if string(value) != test.want {
				t.Fatalf("value mismatch: got %q want %q", value, test.want)
			}
		})
	}
}

func TestResolveFleetImportsSanitizesProviderFailure(t *testing.T) {
	manifest := &fleetconfig.Manifest{Vaults: []fleetconfig.Vault{{
		Name: "automation",
		Imports: []fleetconfig.Import{{
			Name: "TOKEN", Source: "aws-production", Reference: "private/reference",
		}},
	}}}
	plan := &fleetplan.Plan{Operations: []fleetplan.Operation{{
		Resource: fleetplan.ResourceRef{Kind: store.ManagedResourceCredential, Vault: "automation", Name: "TOKEN"},
		Action:   fleetplan.ActionCreate,
	}}}
	providers := fleetImportTestProviders{err: errors.New("private/reference: secret-value-from-upstream")}
	_, err := resolveFleetImports(&cobra.Command{}, manifest, plan, providers)
	if err == nil {
		t.Fatal("provider failure was accepted")
	}
	for _, sensitive := range []string{"private/reference", "secret-value-from-upstream"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("resolution error leaked %q: %v", sensitive, err)
		}
	}
}

var _ fleetImportProviders = fleetImportTestProviders{}
