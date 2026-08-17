package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestCredentialStoreAdapterEnforcesReferenceMaxStaleness(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	vault, _ := db.CreateVault(ctx, "adapter")
	_, _ = db.SetCredential(ctx, vault.ID, "LOCAL", []byte("local"), []byte("nonce"))
	_, _ = db.SetCredential(ctx, vault.ID, "REFERENCE", []byte("cache"), []byte("nonce"))
	adapter := credentialStoreAdapter{Store: db}
	if credential, err := adapter.GetCredential(ctx, vault.ID, "LOCAL"); err != nil || string(credential.Ciphertext) != "local" {
		t.Fatalf("local credential = %#v, %v", credential, err)
	}
	now := time.Now().UTC()
	source := store.CredentialSource{
		VaultID: vault.ID, CredentialKey: "REFERENCE", Mode: store.CredentialSourceModeReference,
		Kind: store.CredentialSourceAWSSecretsManager, ProviderName: "aws", Reference: "secret/app",
		RefreshIntervalSeconds: 60, MaxStalenessSeconds: 30, Health: store.CredentialSourceHealthPending,
	}
	if _, err := db.SetCredentialSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.GetCredential(ctx, vault.ID, "REFERENCE"); !errors.Is(err, store.ErrCredentialStale) {
		t.Fatalf("never-fetched reference = %v", err)
	}
	source.CacheUpdatedAt = &now
	source.LastSuccessAt = &now
	source.Health = store.CredentialSourceHealthError
	if _, err := db.SetCredentialSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	if credential, err := adapter.GetCredential(ctx, vault.ID, "REFERENCE"); err != nil || string(credential.Ciphertext) != "cache" {
		t.Fatalf("fresh last-known-good = %#v, %v", credential, err)
	}
	expired := now.Add(-time.Minute)
	source.CacheUpdatedAt = &expired
	source.LastSuccessAt = &expired
	if _, err := db.SetCredentialSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.GetCredential(ctx, vault.ID, "REFERENCE"); !errors.Is(err, store.ErrCredentialStale) {
		t.Fatalf("expired reference = %v", err)
	}
}
