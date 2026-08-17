package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/keywrap/agerecovery"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

func TestPerformKeyRecoveryPromotesAndAuditsAtomically(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "recovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	original, verification, err := auth.SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Wipe()
	if err := db.SetMasterKeyRecord(ctx, verificationToStoreRecord(verification)); err != nil {
		t.Fatal(err)
	}
	binding, err := keywrap.EnsureInstanceBinding(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	oldPrimary := &commandTestWrapper{identity: keywrap.Identity{Provider: "test-kms", KeyID: "failed-key"}}
	if _, err := keywrap.EnsurePrimary(ctx, db, oldPrimary, original.Key(), binding); err != nil {
		t.Fatal(err)
	}
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := agerecovery.New(ageIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keywrap.EnsureAdditional(ctx, db, recovery, original.Key(), binding); err != nil {
		t.Fatal(err)
	}
	spiffeID := "spiffe://cluster.example/ns/operators/sa/recovery"
	bootstrap, err := db.BootstrapSPIFFEOwners(ctx, []string{spiffeID})
	if err != nil || !bootstrap.Applied {
		t.Fatalf("bootstrap owner = %#v, %v", bootstrap, err)
	}
	actor, err := db.GetAgentBySPIFFEID(ctx, spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	newPrimary := &commandTestWrapper{identity: keywrap.Identity{Provider: "test-kms", KeyID: "replacement-key"}}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := performKeyRecovery(ctx, db, recovery, newPrimary, []byte(wrongIdentity.String()), actor, spiffeID); err == nil {
		t.Fatal("wrong recovery identity succeeded")
	}
	primary, err := db.GetPrimaryDEKWrapping(ctx)
	if err != nil || primary.KeyID != "failed-key" {
		t.Fatalf("failed recovery changed primary = %#v, %v", primary, err)
	}
	events, err := db.ListKeyRecoveryEvents(ctx, 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("failed recovery wrote audit success = %#v, %v", events, err)
	}
	if err := db.UpdateAgentRole(ctx, actor.ID, "member"); err != nil {
		t.Fatal(err)
	}
	if err := performKeyRecovery(ctx, db, recovery, newPrimary, []byte(ageIdentity.String()), actor, spiffeID); err == nil {
		t.Fatal("stale owner authorization was accepted by promotion transaction")
	}
	if err := db.UpdateAgentRole(ctx, actor.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := performKeyRecovery(ctx, db, recovery, newPrimary, []byte(ageIdentity.String()), actor, spiffeID); err != nil {
		t.Fatal(err)
	}
	primary, err = db.GetPrimaryDEKWrapping(ctx)
	if err != nil || primary.KeyID != "replacement-key" {
		t.Fatalf("primary = %#v, %v", primary, err)
	}
	events, err = db.ListKeyRecoveryEvents(ctx, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %#v, %v", events, err)
	}
	event := events[0]
	if event.ActorSPIFFEID != spiffeID || event.ActorID != actor.ID ||
		event.RecoveryProvider != "age-x25519" || event.NewPrimaryKeyID != "replacement-key" {
		t.Fatalf("event = %#v", event)
	}
	if bytes.Contains([]byte(event.RecoveryKeyID+event.NewPrimaryKeyID), original.Key()) {
		t.Fatal("audit metadata contained DEK bytes")
	}
}

func TestPerformKeyRecoveryRejectsNonOwnerBeforeUnwrap(t *testing.T) {
	actor := &store.Agent{ID: "member", SPIFFEID: "spiffe://example/member", Role: "member", Status: "active"}
	err := performKeyRecovery(context.Background(), nil, nil, nil, []byte("identity"), actor, actor.SPIFFEID)
	if err == nil || err.Error() != "key recovery requires an active SPIFFE instance owner" {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestReadRecoveryIdentityRequiresPrivateFileOrStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte("AGE-SECRET-KEY-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	identity, err := readRecoveryIdentity(cmd, path)
	if err != nil || string(identity) != "AGE-SECRET-KEY-test" {
		t.Fatalf("private file = %q, %v", identity, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryIdentity(cmd, path); err == nil {
		t.Fatal("group/world-readable recovery identity was accepted")
	}
	cmd.SetIn(strings.NewReader("AGE-SECRET-KEY-stdin"))
	identity, err = readRecoveryIdentity(cmd, "-")
	if err != nil || string(identity) != "AGE-SECRET-KEY-stdin" {
		t.Fatalf("stdin identity = %q, %v", identity, err)
	}
}
