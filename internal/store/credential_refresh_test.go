package store

import (
	"context"
	"testing"
	"time"
)

func TestCredentialRefreshClaimsAndAtomicCompletion(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, _ := s.CreateVault(ctx, "refresh-claims")
	now := time.Now().UTC().Truncate(time.Second)
	for _, key := range []string{"A", "B"} {
		if _, err := s.SetCredential(ctx, vault.ID, key, []byte("old-"+key), []byte("nonce-"+key)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetCredentialSource(ctx, CredentialSource{
			VaultID: vault.ID, CredentialKey: key, Mode: CredentialSourceModeReference,
			Kind: CredentialSourceAWSSecretsManager, ProviderName: "aws", Reference: "secret/" + key,
			RefreshIntervalSeconds: 60, MaxStalenessSeconds: 300,
			Health: CredentialSourceHealthPending, NextRefreshAt: timePtr(now.Add(-time.Second)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := s.ClaimCredentialSources(ctx, "replica-a", now, time.Minute, 1)
	if err != nil || len(claimed) != 1 || claimed[0].ClaimOwner != "replica-a" {
		t.Fatalf("first claim = %#v, %v", claimed, err)
	}
	other, err := s.ClaimCredentialSources(ctx, "replica-b", now, time.Minute, 10)
	if err != nil || len(other) != 1 || other[0].CredentialKey == claimed[0].CredentialKey {
		t.Fatalf("second claim = %#v, %v", other, err)
	}

	completion := CredentialRefreshCompletion{
		VaultID: vault.ID, CredentialKey: claimed[0].CredentialKey, ClaimOwner: "wrong-replica",
		ProviderVersion: "v1", Ciphertext: []byte("new-ct"), Nonce: []byte("new-nonce"), ValueChanged: true,
		RefreshedAt: now, NextRefreshAt: now.Add(time.Minute),
	}
	if applied, err := s.CompleteCredentialRefresh(ctx, completion); err != nil || applied {
		t.Fatalf("wrong owner completion = %v, %v", applied, err)
	}
	completion.ClaimOwner = "replica-a"
	if applied, err := s.CompleteCredentialRefresh(ctx, completion); err != nil || !applied {
		t.Fatalf("owner completion = %v, %v", applied, err)
	}
	credential, err := s.GetCredential(ctx, vault.ID, claimed[0].CredentialKey)
	if err != nil || string(credential.Ciphertext) != "new-ct" {
		t.Fatalf("atomic cache = %#v, %v", credential, err)
	}
	source, err := s.GetCredentialSource(ctx, vault.ID, claimed[0].CredentialKey)
	if err != nil || source.Health != CredentialSourceHealthOK || source.ProviderVersion != "v1" ||
		source.ClaimOwner != "" || source.LastSuccessAt == nil || source.RefreshFailures != 0 {
		t.Fatalf("completed source = %#v, %v", source, err)
	}
}

func TestCredentialRefreshFailureBackoffAndExpiredClaim(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, _ := s.CreateVault(ctx, "refresh-failure")
	now := time.Now().UTC().Truncate(time.Second)
	_, _ = s.SetCredential(ctx, vault.ID, "TOKEN", []byte("cache"), []byte("nonce"))
	_, err := s.SetCredentialSource(ctx, CredentialSource{
		VaultID: vault.ID, CredentialKey: "TOKEN", Mode: CredentialSourceModeReference,
		Kind: CredentialSourceOpenBaoKV2, ProviderName: "bao", Reference: "kv/app#token",
		RefreshIntervalSeconds: 60, MaxStalenessSeconds: 10,
		Health: CredentialSourceHealthOK, CacheUpdatedAt: timePtr(now.Add(-time.Hour)),
		LastSuccessAt: timePtr(now.Add(-time.Hour)), NextRefreshAt: timePtr(now.Add(-time.Second)),
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimCredentialSources(ctx, "crashed", now, 5*time.Second, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("initial claim = %#v, %v", claimed, err)
	}
	if claimed, err = s.ClaimCredentialSources(ctx, "takeover", now.Add(6*time.Second), time.Minute, 10); err != nil || len(claimed) != 1 {
		t.Fatalf("expired takeover = %#v, %v", claimed, err)
	}
	next := now.Add(30 * time.Second)
	applied, err := s.FailCredentialRefresh(ctx, CredentialRefreshFailure{
		VaultID: vault.ID, CredentialKey: "TOKEN", ClaimOwner: "takeover",
		ErrorCode: "provider_unavailable", Health: CredentialSourceHealthStale,
		AttemptedAt: now.Add(6 * time.Second), NextRefreshAt: next,
	})
	if err != nil || !applied {
		t.Fatalf("failure = %v, %v", applied, err)
	}
	source, err := s.GetCredentialSource(ctx, vault.ID, "TOKEN")
	if err != nil || source.Health != CredentialSourceHealthStale || source.RefreshFailures != 1 ||
		source.ClaimOwner != "" || source.NextRefreshAt == nil || !source.NextRefreshAt.Equal(next) {
		t.Fatalf("failed source = %#v, %v", source, err)
	}
	if CredentialSourceUsable(source, now) {
		t.Fatal("expired last-known-good cache remained usable")
	}
	if claimed, err = s.ClaimCredentialSources(ctx, "early", now.Add(20*time.Second), time.Minute, 10); err != nil || len(claimed) != 0 {
		t.Fatalf("backoff was ignored = %#v, %v", claimed, err)
	}
}

func timePtr(value time.Time) *time.Time { return &value }
