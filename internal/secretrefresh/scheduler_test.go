package secretrefresh

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
)

type providerReference string

func (r providerReference) ProviderKind() string { return secretprovider.KindAWSSecretsManager }
func (r providerReference) Canonical() string    { return string(r) }

type controlledProvider struct {
	mu      sync.Mutex
	value   []byte
	version string
	err     error
	count   int
}

func (p *controlledProvider) Kind() string { return secretprovider.KindAWSSecretsManager }
func (p *controlledProvider) ParseReference(raw string) (secretprovider.Reference, error) {
	if raw != "secret/app#token" && raw != "secret/stale#token" {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return providerReference(raw), nil
}
func (p *controlledProvider) Fetch(context.Context, secretprovider.Reference) (secretprovider.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	if p.err != nil {
		return secretprovider.Result{}, p.err
	}
	return secretprovider.NewResult(p.value, p.version)
}
func (p *controlledProvider) set(value []byte, version string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.value = append([]byte(nil), value...)
	p.version = version
	p.err = err
}
func (p *controlledProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

func TestSchedulersClaimOnceEncryptCacheAndSkipUnchangedVersion(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scheduler.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	vault, _ := db.CreateVault(ctx, "scheduler")
	dek := bytes.Repeat([]byte{7}, 32)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := db.SetCredential(ctx, vault.ID, "TOKEN", []byte("placeholder"), []byte("placeholder")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetCredentialSource(ctx, store.CredentialSource{
		VaultID: vault.ID, CredentialKey: "TOKEN", Mode: store.CredentialSourceModeReference,
		Kind: secretprovider.KindAWSSecretsManager, ProviderName: "aws", Reference: "secret/app#token",
		RefreshIntervalSeconds: 60, MaxStalenessSeconds: 300,
		Health: store.CredentialSourceHealthPending, NextRefreshAt: ptrTime(now.Add(-time.Second)),
	}); err != nil {
		t.Fatal(err)
	}
	provider := &controlledProvider{value: []byte("first-secret"), version: "version-1"}
	registry := secretprovider.NewRegistry()
	if err := registry.Register("aws", provider); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	newScheduler := func(worker string) *Scheduler {
		scheduler, err := New(Options{
			Store: db, Registry: registry, EncryptionKey: dek, WorkerID: worker,
			ClaimLease: time.Minute, BatchSize: 10, Now: func() time.Time { return now },
			Random: func() float64 { return 0.5 },
		})
		if err != nil {
			t.Fatal(err)
		}
		return scheduler
	}
	first := newScheduler("replica-a")
	second := newScheduler("replica-b")
	defer first.Close()
	defer second.Close()
	var wg sync.WaitGroup
	stats := make(chan Stats, 2)
	errs := make(chan error, 2)
	for _, scheduler := range []*Scheduler{first, second} {
		wg.Add(1)
		go func(scheduler *Scheduler) {
			defer wg.Done()
			result, err := scheduler.RunOnce(ctx)
			stats <- result
			errs <- err
		}(scheduler)
	}
	wg.Wait()
	close(stats)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var total Stats
	for result := range stats {
		total.Claimed += result.Claimed
		total.Updated += result.Updated
	}
	if total.Claimed != 1 || total.Updated != 1 || provider.calls() != 1 {
		t.Fatalf("stampede stats = %#v, provider calls = %d", total, provider.calls())
	}
	credential, err := db.GetCredential(ctx, vault.ID, "TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := vaultcrypto.Decrypt(credential.Ciphertext, credential.Nonce, dek)
	if err != nil || string(plaintext) != "first-secret" {
		t.Fatalf("encrypted cache = %q, %v", plaintext, err)
	}
	vaultcrypto.WipeBytes(plaintext)
	source, err := db.GetCredentialSource(ctx, vault.ID, "TOKEN")
	if err != nil || source.ProviderVersion != "version-1" || source.LastSuccessAt == nil ||
		source.NextRefreshAt == nil || !store.CredentialSourceUsable(source, now) {
		t.Fatalf("refreshed source = %#v, %v", source, err)
	}

	// An opaque version match updates freshness but does not rewrite cache.
	originalCiphertext := append([]byte(nil), credential.Ciphertext...)
	provider.set([]byte("provider-bug-different-value"), "version-1", nil)
	source.NextRefreshAt = ptrTime(now.Add(-time.Second))
	if _, err := db.SetCredentialSource(ctx, *source); err != nil {
		t.Fatal(err)
	}
	result, err := first.RunOnce(ctx)
	if err != nil || result.Unchanged != 1 {
		t.Fatalf("unchanged refresh = %#v, %v", result, err)
	}
	credential, _ = db.GetCredential(ctx, vault.ID, "TOKEN")
	if !bytes.Equal(credential.Ciphertext, originalCiphertext) {
		t.Fatal("unchanged provider version rewrote encrypted cache")
	}
}

func TestSchedulerBackoffAndMaxStalenessFailClosed(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "staleness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	vault, _ := db.CreateVault(ctx, "staleness")
	dek := bytes.Repeat([]byte{4}, 32)
	now := time.Now().UTC().Truncate(time.Second)
	cacheTime := now.Add(-time.Minute)
	if _, err := db.SetCredential(ctx, vault.ID, "STALE", []byte("encrypted"), []byte("nonce")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetCredentialSource(ctx, store.CredentialSource{
		VaultID: vault.ID, CredentialKey: "STALE", Mode: store.CredentialSourceModeReference,
		Kind: secretprovider.KindAWSSecretsManager, ProviderName: "aws", Reference: "secret/stale#token",
		RefreshIntervalSeconds: 60, MaxStalenessSeconds: 10, Health: store.CredentialSourceHealthOK,
		CacheUpdatedAt: &cacheTime, LastSuccessAt: &cacheTime, NextRefreshAt: ptrTime(now.Add(-time.Second)),
	}); err != nil {
		t.Fatal(err)
	}
	provider := &controlledProvider{err: errors.New("SDK SECRET-PAYLOAD")}
	registry := secretprovider.NewRegistry()
	_ = registry.Register("aws", provider)
	scheduler, err := New(Options{
		Store: db, Registry: registry, EncryptionKey: dek, WorkerID: "replica",
		ClaimLease: time.Minute, BaseBackoff: 5 * time.Second, MaxBackoff: time.Minute,
		Now: func() time.Time { return now }, Random: func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close()
	result, err := scheduler.RunOnce(ctx)
	if err != nil || result.Failed != 1 {
		t.Fatalf("failed refresh = %#v, %v", result, err)
	}
	source, err := db.GetCredentialSource(ctx, vault.ID, "STALE")
	if err != nil {
		t.Fatal(err)
	}
	if source.Health != store.CredentialSourceHealthStale || source.LastErrorCode != string(secretprovider.CodeUnavailable) ||
		source.RefreshFailures != 1 || source.NextRefreshAt == nil || !source.NextRefreshAt.Equal(now.Add(5*time.Second)) ||
		store.CredentialSourceUsable(source, now) {
		t.Fatalf("stale source = %#v", source)
	}
	if bytes.Contains([]byte(source.LastErrorCode), []byte("SECRET")) {
		t.Fatal("provider failure payload reached source metadata")
	}
	// Backoff prevents early re-fetch; first failure doubles on the next due
	// attempt from five to ten seconds.
	now = now.Add(5 * time.Second)
	if result, err = scheduler.RunOnce(ctx); err != nil || result.Failed != 1 {
		t.Fatalf("second failure = %#v, %v", result, err)
	}
	source, _ = db.GetCredentialSource(ctx, vault.ID, "STALE")
	if source.NextRefreshAt == nil || !source.NextRefreshAt.Equal(now.Add(10*time.Second)) || source.RefreshFailures != 2 {
		t.Fatalf("exponential backoff = %#v", source)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
