package keywrap

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestEnsurePrimaryAddBeforeRetireAndLegacyMigration(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "wrapping.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	dek := bytes.Repeat([]byte{6}, 32)
	if err := db.SetMasterKeyRecord(ctx, &store.MasterKeyRecord{
		Sentinel: []byte("sentinel"), SentinelNonce: []byte("nonce"),
		DEKPlaintext: append([]byte(nil), dek...), DEKCiphertext: []byte("legacy-password-copy"),
	}); err != nil {
		t.Fatal(err)
	}
	binding, err := EnsureInstanceBinding(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	first := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "key-one"}}
	primary, err := EnsurePrimary(ctx, db, first, dek, binding)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.DEKPlaintext != nil || string(legacy.DEKCiphertext) != "legacy-password-copy" {
		t.Fatalf("legacy migration state = %#v", legacy)
	}

	bad := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "key-two"}, wrong: true}
	if _, err := EnsurePrimary(ctx, db, bad, dek, binding); err == nil {
		t.Fatal("unverified rotation succeeded")
	}
	stillPrimary, err := db.GetPrimaryDEKWrapping(ctx)
	if err != nil || stillPrimary.ID != primary.ID {
		t.Fatalf("failed rotation lost primary: %#v, %v", stillPrimary, err)
	}

	second := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "key-two"}}
	rotated, err := EnsurePrimary(ctx, db, second, dek, binding)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ID == primary.ID || rotated.KeyID != "key-two" {
		t.Fatalf("rotation did not promote new wrapping: %#v", rotated)
	}
	records, err := db.ListDEKWrappings(ctx, false)
	if err != nil || len(records) != 2 || records[1].Status != store.DEKWrappingActive {
		t.Fatalf("coexisting wrappings = %#v, %v", records, err)
	}
}

func TestConcurrentReplicasConvergeOnOnePrimary(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "converge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	dek := bytes.Repeat([]byte{2}, 32)
	if err := db.SetMasterKeyRecord(ctx, &store.MasterKeyRecord{Sentinel: []byte("s"), SentinelNonce: []byte("n"), DEKPlaintext: append([]byte(nil), dek...)}); err != nil {
		t.Fatal(err)
	}
	binding, err := EnsureInstanceBinding(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "shared-key"}}
	const replicas = 8
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := EnsurePrimary(ctx, db, wrapper, dek, binding)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	records, err := db.ListDEKWrappings(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != store.DEKWrappingPrimary {
		t.Fatalf("replicas did not converge: %#v", records)
	}
	if time.Since(records[0].VerifiedAt) > time.Minute {
		t.Fatal("unexpected verification timestamp")
	}
}

func TestRecoveryAuditFailureRollsBackPromotion(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "audit-rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	dek := bytes.Repeat([]byte{9}, 32)
	if err := db.SetMasterKeyRecord(ctx, &store.MasterKeyRecord{
		Sentinel: []byte("s"), SentinelNonce: []byte("n"), DEKPlaintext: append([]byte(nil), dek...),
	}); err != nil {
		t.Fatal(err)
	}
	binding, err := EnsureInstanceBinding(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	oldWrapper := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "old"}}
	oldPrimary, err := EnsurePrimary(ctx, db, oldWrapper, dek, binding)
	if err != nil {
		t.Fatal(err)
	}
	newWrapper := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "new"}}
	_, err = EnsureRecoveryPrimary(ctx, db, newWrapper, dek, binding, store.KeyRecoveryEvent{
		ActorID: "owner", ActorSPIFFEID: "spiffe://example/owner", RecoveryWrappingID: "missing",
	})
	if err == nil {
		t.Fatal("promotion succeeded without a recovery audit source")
	}
	primary, err := db.GetPrimaryDEKWrapping(ctx)
	if err != nil || primary.ID != oldPrimary.ID {
		t.Fatalf("unaudited promotion was not rolled back: %#v, %v", primary, err)
	}
	events, err := db.ListKeyRecoveryEvents(ctx, 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("unexpected recovery events = %#v, %v", events, err)
	}
}
