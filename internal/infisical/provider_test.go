package infisical

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
	sdkerrors "github.com/infisical/go-sdk/packages/errors"
)

type providerFetcher struct {
	configs []VaultConfig
	keys    []string
	secret  Secret
	err     error
}

func (f *providerFetcher) FetchSecret(_ context.Context, config VaultConfig, key string) (Secret, error) {
	f.configs = append(f.configs, config)
	f.keys = append(f.keys, key)
	return f.secret, f.err
}

func (f *providerFetcher) AuthMethod() AuthMethod { return AuthKubernetes }

func TestProviderSupportsSharedAndLegacyReferences(t *testing.T) {
	legacy := VaultConfig{ProjectID: "legacy-project", Environment: "prod", SecretPath: "/legacy"}
	provider, err := NewProvider(ProviderOptions{Fetcher: &providerFetcher{}, LegacyConfig: &legacy})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]ProviderReference{
		"LEGACY_TOKEN": {
			config: legacy, key: "LEGACY_TOKEN", legacy: true, canonical: "LEGACY_TOKEN",
		},
		"project-id/staging/application/api#TOKEN": {
			config: VaultConfig{ProjectID: "project-id", Environment: "staging", SecretPath: "/application/api"},
			key:    "TOKEN", canonical: "project-id/staging/application/api#TOKEN",
		},
		"project-id/prod#api%20key": {
			config: VaultConfig{ProjectID: "project-id", Environment: "prod", SecretPath: "/"},
			key:    "api key", canonical: "project-id/prod#api%20key",
		},
	}
	for raw, expected := range tests {
		reference, err := provider.ParseReference(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := reference.(ProviderReference); got != expected || got.Canonical() != expected.canonical {
			t.Fatalf("parse %q = %#v, want %#v", raw, got, expected)
		}
	}
}

func TestProviderRejectsUnsafeAndAmbiguousReferences(t *testing.T) {
	provider, err := NewProvider(ProviderOptions{Fetcher: &providerFetcher{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"", "TOKEN", "project#TOKEN", "project/prod#", "project//path#TOKEN",
		"project/prod/../path#TOKEN", "project/prod/path#TOKEN#again", " project/prod#TOKEN",
		"project/prod#TOKEN\nvalue", "project/prod/%2Fetc#TOKEN",
	} {
		if _, err := provider.ParseReference(raw); secretprovider.CodeOf(err) != secretprovider.CodeInvalidReference {
			t.Fatalf("reference %q error = %v (%s)", raw, err, secretprovider.CodeOf(err))
		}
	}
}

func TestProviderFetchesExactStaticSecretAndVersionsChanges(t *testing.T) {
	fetcher := &providerFetcher{secret: Secret{ID: "secret-id", Key: "TOKEN", Value: "SECRET-ONE", Version: 4}}
	provider, err := NewProvider(ProviderOptions{Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := provider.ParseReference("project/prod/app#TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Bytes()) != "SECRET-ONE" || result.Version() != "secret-id:4" {
		t.Fatalf("result = %q @ %q", result.Bytes(), result.Version())
	}
	result.Wipe()
	fetcher.secret.Value = "SECRET-TWO"
	fetcher.secret.Version = 5
	result, err = provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Wipe()
	if string(result.Bytes()) != "SECRET-TWO" || result.Version() != "secret-id:5" {
		t.Fatalf("rotated result = %q @ %q", result.Bytes(), result.Version())
	}
	if len(fetcher.configs) != 2 || fetcher.configs[0].SecretPath != "/app" || fetcher.keys[0] != "TOKEN" {
		t.Fatalf("fetch configurations = %#v", fetcher.configs)
	}
}

func TestProviderSanitizesMissingDuplicateAndUpstreamFailures(t *testing.T) {
	tests := []struct {
		name   string
		secret Secret
		err    error
		code   secretprovider.ErrorCode
	}{
		{name: "missing", code: secretprovider.CodeNotFound},
		{name: "mismatched response", secret: Secret{Key: "OTHER", Value: "SECRET-1"}, code: secretprovider.CodeInvalidResponse},
		{name: "not found upstream", err: &sdkerrors.APIError{StatusCode: http.StatusNotFound, ErrorMessage: "SECRET-PATH"}, code: secretprovider.CodeNotFound},
		{name: "access denied upstream", err: &sdkerrors.APIError{StatusCode: http.StatusForbidden, ErrorMessage: "SECRET-POLICY"}, code: secretprovider.CodeAccessDenied},
		{name: "upstream", err: errors.New("SECRET-UPSTREAM"), code: secretprovider.CodeUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := NewProvider(ProviderOptions{Fetcher: &providerFetcher{secret: test.secret, err: test.err}})
			if err != nil {
				t.Fatal(err)
			}
			reference, err := provider.ParseReference("project/prod#TOKEN")
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Fetch(context.Background(), reference)
			if secretprovider.CodeOf(err) != test.code {
				t.Fatalf("error = %v (%s), want %s", err, secretprovider.CodeOf(err), test.code)
			}
			for _, secret := range []string{"SECRET-1", "SECRET-PATH", "SECRET-POLICY", "SECRET-UPSTREAM"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked provider data: %v", err)
				}
			}
		})
	}
}

type legacyStore struct{ stores []store.VaultCredentialStore }

func (s legacyStore) ListVaultCredentialStores(context.Context) ([]store.VaultCredentialStore, error) {
	return s.stores, nil
}

func TestRegisterLegacyProvidersPreservesEachVaultConfiguration(t *testing.T) {
	configA, _ := MarshalConfigJSON(VaultConfig{ProjectID: "project-a", Environment: "prod", SecretPath: "/a"})
	configB, _ := MarshalConfigJSON(VaultConfig{ProjectID: "project-b", Environment: "dev", SecretPath: "/b"})
	registry := secretprovider.NewRegistry()
	fetcher := &providerFetcher{secret: Secret{ID: "id", Key: "TOKEN", Value: "SECRET", Version: 1}}
	err := RegisterLegacyProviders(context.Background(), registry, legacyStore{stores: []store.VaultCredentialStore{
		{VaultID: "11111111-1111-1111-1111-111111111111", Kind: store.CredentialStoreInfisical, ConfigJSON: configA},
		{VaultID: "22222222-2222-2222-2222-222222222222", Kind: store.CredentialStoreInfisical, ConfigJSON: configB},
		{VaultID: "33333333-3333-3333-3333-333333333333", Kind: store.CredentialStoreBuiltin},
	}}, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"legacy-infisical-11111111-1111-1111-1111-111111111111",
		"legacy-infisical-22222222-2222-2222-2222-222222222222",
	}
	if strings.Join(registry.Names(), ",") != strings.Join(wantNames, ",") {
		t.Fatalf("provider names = %#v", registry.Names())
	}
	for i, name := range wantNames {
		result, err := registry.Fetch(context.Background(), name, "TOKEN")
		if err != nil {
			t.Fatal(err)
		}
		result.Wipe()
		if fetcher.configs[i].ProjectID != []string{"project-a", "project-b"}[i] {
			t.Fatalf("fetch config %d = %#v", i, fetcher.configs[i])
		}
	}
}
