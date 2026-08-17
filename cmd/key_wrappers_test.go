package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/Infisical/agent-vault/internal/auth"
	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/keywrap/agerecovery"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

type commandTestWrapper struct {
	identity keywrap.Identity
	fail     bool
}

func (w *commandTestWrapper) Identity() keywrap.Identity { return w.identity }
func (w *commandTestWrapper) Wrap(_ context.Context, plaintext []byte, _ keywrap.Binding) (keywrap.WrappedDEK, error) {
	if w.fail {
		return keywrap.WrappedDEK{}, errors.New("provider unavailable")
	}
	return keywrap.WrappedDEK{Ciphertext: append([]byte("wrapped:"), plaintext...), KeyVersion: "1"}, nil
}
func (w *commandTestWrapper) Unwrap(_ context.Context, wrapped keywrap.WrappedDEK, _ keywrap.Binding) ([]byte, error) {
	if w.fail || !bytes.HasPrefix(wrapped.Ciphertext, []byte("wrapped:")) {
		return nil, errors.New("provider unavailable")
	}
	return append([]byte(nil), wrapped.Ciphertext[len("wrapped:"):]...), nil
}

func TestConfiguredWrapperMigrationAndFailClosedStartup(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "wrapped.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	original, verification, err := auth.SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Wipe()
	if err := db.SetMasterKeyRecord(context.Background(), verificationToStoreRecord(verification)); err != nil {
		t.Fatal(err)
	}
	primary := &commandTestWrapper{identity: keywrap.Identity{Provider: "test-kms", KeyID: "key-one"}}
	ageIdentity, _ := age.GenerateX25519Identity()
	recovery, err := agerecovery.New(ageIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	wrappers := map[string]keywrap.KeyWrapper{"primary": primary, "recovery": recovery}
	encryption := runtimeconfig.Encryption{PrimaryWrapper: "primary"}
	cmd := &cobra.Command{}

	unlocked, err := unlockOrSetupWithWrapperSet(cmd, db, false, encryption, wrappers)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unlocked.Key(), original.Key()) {
		t.Fatal("migration changed DEK")
	}
	unlocked.Wipe()
	record, _ := db.GetMasterKeyRecord(context.Background())
	if record.DEKPlaintext != nil {
		t.Fatal("verified provider migration left plaintext DEK")
	}
	rows, err := db.ListDEKWrappings(context.Background(), false)
	if err != nil || len(rows) != 2 || rows[0].Status != store.DEKWrappingPrimary {
		t.Fatalf("wrappings = %#v, %v", rows, err)
	}
	second := &commandTestWrapper{identity: keywrap.Identity{Provider: "test-kms", KeyID: "key-two"}}
	wrappers["second"] = second
	encryption.PrimaryWrapper = "second"
	rotated, err := unlockOrSetupWithWrapperSet(cmd, db, false, encryption, wrappers)
	if err != nil {
		t.Fatal(err)
	}
	rotated.Wipe()
	rows, err = db.ListDEKWrappings(context.Background(), false)
	if err != nil || len(rows) != 3 || rows[0].KeyID != "key-two" || rows[0].Status != store.DEKWrappingPrimary {
		t.Fatalf("rotated wrappings = %#v, %v", rows, err)
	}

	// Even if legacy plaintext reappears during a rolling-version accident,
	// an established provider primary never downgrades to it on outage.
	record.DEKPlaintext = append([]byte(nil), original.Key()...)
	if err := db.UpdateMasterKeyRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	second.fail = true
	if _, err := unlockOrSetupWithWrapperSet(cmd, db, false, encryption, wrappers); err == nil {
		t.Fatal("provider outage downgraded to legacy plaintext")
	}
}
