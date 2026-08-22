package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCredentialSourcesAllowMixedVaultAndLocalConversion(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.CreateVault(ctx, "mixed-sources")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetCredential(ctx, vault.ID, "LOCAL", []byte("local-ct"), []byte("local-nonce")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetCredential(ctx, vault.ID, "AWS", []byte("cached-ct"), []byte("cached-nonce")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	source, err := s.SetCredentialSource(ctx, CredentialSource{
		VaultID: vault.ID, CredentialKey: "AWS", Mode: CredentialSourceModeReference,
		Kind: CredentialSourceAWSSecretsManager, ProviderName: "aws-production",
		Reference:              "arn:aws:secretsmanager:us-east-1:123:secret:app#token",
		RefreshIntervalSeconds: 300, MaxStalenessSeconds: 3600,
		ProviderVersion: "version-1", Health: CredentialSourceHealthOK,
		CacheUpdatedAt: &now, LastRefreshAt: &now, LastSuccessAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.Kind != CredentialSourceAWSSecretsManager || source.ProviderVersion != "version-1" {
		t.Fatalf("source = %#v", source)
	}
	sources, err := s.ListCredentialSources(ctx, vault.ID)
	if err != nil || len(sources) != 1 || sources[0].CredentialKey != "AWS" {
		t.Fatalf("mixed sources = %#v, %v", sources, err)
	}
	local, err := s.GetCredential(ctx, vault.ID, "LOCAL")
	if err != nil || string(local.Ciphertext) != "local-ct" {
		t.Fatalf("local cache = %#v, %v", local, err)
	}

	// A direct set or one-time import converts only that credential back to
	// local and atomically removes the live relationship.
	if _, err := s.SetCredential(ctx, vault.ID, "AWS", []byte("imported-ct"), []byte("imported-nonce")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCredentialSource(ctx, vault.ID, "AWS"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("direct import retained source: %v", err)
	}
	credential, err := s.GetCredential(ctx, vault.ID, "AWS")
	if err != nil || string(credential.Ciphertext) != "imported-ct" {
		t.Fatalf("imported cache = %#v, %v", credential, err)
	}
}

func TestLegacyInfisicalStoreMigratesAndDetachesPerCredentialSources(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, "source-owner@example.com", []byte("hash"), []byte("salt"), "owner", 3, 65536, 4)
	if err != nil {
		t.Fatal(err)
	}
	configJSON := `{"project_id":"project","environment":"prod","secret_path":"/app"}`
	vault, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name: "legacy-sources", Kind: CredentialStoreInfisical, ConfigJSON: configJSON,
		PollIntervalSeconds: 60,
		Credentials: []EncryptedKV{
			{Key: "TOKEN", Ciphertext: []byte("token-ct"), Nonce: []byte("token-nonce")},
			{Key: "PASSWORD", Ciphertext: []byte("password-ct"), Nonce: []byte("password-nonce")},
		},
		CreatorActorID: owner.ID, CreatorActorType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := s.ListCredentialSources(ctx, vault.ID)
	if err != nil || len(sources) != 2 {
		t.Fatalf("legacy sources = %#v, %v", sources, err)
	}
	for _, source := range sources {
		if source.Kind != CredentialSourceInfisical || source.Mode != CredentialSourceModeReference ||
			source.ProviderName != "legacy-infisical-"+vault.ID || source.Reference != source.CredentialKey ||
			source.MaxStalenessSeconds != 0 || source.CacheUpdatedAt == nil {
			t.Fatalf("legacy source = %#v", source)
		}
	}

	applied, err := s.ReplaceVaultCredentialsForSync(ctx, vault.ID, configJSON, []EncryptedKV{
		{Key: "ROTATED", Ciphertext: []byte("rotated-ct"), Nonce: []byte("rotated-nonce")},
	})
	if err != nil || !applied {
		t.Fatalf("legacy refresh = %v, %v", applied, err)
	}
	sources, err = s.ListCredentialSources(ctx, vault.ID)
	if err != nil || len(sources) != 1 || sources[0].CredentialKey != "ROTATED" {
		t.Fatalf("refreshed sources = %#v, %v", sources, err)
	}
	if err := s.UpdateVaultCredentialStoreHealth(ctx, vault.ID, SyncStatusError, "SECRET-UPSTREAM-PAYLOAD", time.Now()); err != nil {
		t.Fatal(err)
	}
	source, err := s.GetCredentialSource(ctx, vault.ID, "ROTATED")
	if err != nil {
		t.Fatal(err)
	}
	if source.Health != CredentialSourceHealthError || source.LastErrorCode != "legacy-sync-error" ||
		strings.Contains(source.LastErrorCode, "SECRET") {
		t.Fatalf("unsanitized legacy health = %#v", source)
	}

	if err := s.DeleteVaultCredentialStore(ctx, vault.ID); err != nil {
		t.Fatal(err)
	}
	sources, err = s.ListCredentialSources(ctx, vault.ID)
	if err != nil || len(sources) != 0 {
		t.Fatalf("detached sources = %#v, %v", sources, err)
	}
	credentials, err := s.ListCredentials(ctx, vault.ID)
	if err != nil || len(credentials) != 1 || credentials[0].Key != "ROTATED" {
		t.Fatalf("detached cache was lost = %#v, %v", credentials, err)
	}
}

func TestCredentialSourceValidationRejectsInlineOrExecutableMetadata(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, _ := s.CreateVault(ctx, "invalid-source")
	_, _ = s.SetCredential(ctx, vault.ID, "TOKEN", []byte("ct"), []byte("nonce"))
	base := CredentialSource{
		VaultID: vault.ID, CredentialKey: "TOKEN", Mode: CredentialSourceModeReference,
		Kind: CredentialSourceAWSSecretsManager, ProviderName: "aws", Reference: "valid-ref",
		RefreshIntervalSeconds: 60, MaxStalenessSeconds: 300, Health: CredentialSourceHealthPending,
	}
	for _, mutate := range []func(*CredentialSource){
		func(source *CredentialSource) { source.Mode = "inline" },
		func(source *CredentialSource) { source.Kind = "exec" },
		func(source *CredentialSource) { source.Reference = "exec://command\nargument" },
		func(source *CredentialSource) { source.RefreshIntervalSeconds = 1 },
	} {
		source := base
		mutate(&source)
		if _, err := s.SetCredentialSource(ctx, source); err == nil {
			t.Fatalf("invalid source accepted: %#v", source)
		}
	}
}

func TestCredentialSourceMigrationBackfillsExistingExternalVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-source.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, "migration-owner@example.com", []byte("hash"), []byte("salt"), "owner", 3, 65536, 4)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name: "pre-source", Kind: CredentialStoreInfisical,
		ConfigJSON:          `{"project_id":"project","environment":"prod","secret_path":"/"}`,
		PollIntervalSeconds: 120,
		Credentials:         []EncryptedKV{{Key: "TOKEN", Ciphertext: []byte("encrypted-cache"), Nonce: []byte("nonce")}},
		CreatorActorID:      owner.ID, CreatorActorType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the immediately pre-migration schema while retaining the
	// legacy vault store and encrypted cache rows.
	if _, err := s.db.Exec(`DROP TABLE credential_sources`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations WHERE name IN (
		'20260817200000_add_credential_sources', '20260817201000_add_credential_refresh_claims')`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source, err := s.GetCredentialSource(ctx, vault.ID, "TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if source.Kind != CredentialSourceInfisical || source.ProviderName != "legacy-infisical-"+vault.ID ||
		source.Reference != "TOKEN" || source.RefreshIntervalSeconds != 120 || source.CacheUpdatedAt == nil {
		t.Fatalf("backfilled source = %#v", source)
	}
	credential, err := s.GetCredential(ctx, vault.ID, "TOKEN")
	if err != nil || string(credential.Ciphertext) != "encrypted-cache" {
		t.Fatalf("backfill lost encrypted cache = %#v, %v", credential, err)
	}
}
