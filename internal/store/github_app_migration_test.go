package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestGitHubAppMigrationKeepsSPIFFEJWTSVIDSource(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "upgrade.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := s.CreateVault(ctx, "jwt-svid")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"K8S_TOKEN", "GITHUB"} {
		if _, err := s.SetCredential(ctx, vault.ID, key, []byte("ct"), []byte("nonce")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetCredentialSource(ctx, CredentialSource{
		VaultID: vault.ID, CredentialKey: "K8S_TOKEN", Mode: CredentialSourceModeReference,
		Kind: CredentialSourceSPIFFEJWTSVID, ProviderName: "spire",
		Reference:              "spiffe://example.org/agent/read?audience=kubernetes",
		RefreshIntervalSeconds: 20, MaxStalenessSeconds: 60, Health: CredentialSourceHealthPending,
	}); err != nil {
		t.Fatal(err)
	}
	// Run the github-app migration again over a database that holds a
	// spiffe-jwt-svid row, as an upgrade of a live instance does.
	if _, err := s.db.Exec("DELETE FROM schema_migrations WHERE name = '20261011120000_allow_github_app_credential_source'"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen after github-app migration: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	got, err := s.GetCredentialSource(ctx, vault.ID, "K8S_TOKEN")
	if err != nil || got.Kind != CredentialSourceSPIFFEJWTSVID {
		t.Fatalf("spiffe source after migration = %#v, %v", got, err)
	}
	if _, err := s.SetCredentialSource(ctx, CredentialSource{
		VaultID: vault.ID, CredentialKey: "GITHUB", Mode: CredentialSourceModeReference,
		Kind: CredentialSourceGitHubApp, ProviderName: "axel", Reference: "token",
		RefreshIntervalSeconds: 300, MaxStalenessSeconds: 600, Health: CredentialSourceHealthPending,
	}); err != nil {
		t.Fatalf("github-app save after migration: %v", err)
	}
}
