package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/Infisical/agent-vault/internal/auth"
	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/keywrap/agerecovery"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

type encryptedFaultWrapper struct {
	mu       sync.RWMutex
	identity keywrap.Identity
	key      []byte
	outage   bool
	corrupt  bool
}

func newEncryptedFaultWrapper(provider, keyID string, fill byte) *encryptedFaultWrapper {
	return &encryptedFaultWrapper{
		identity: keywrap.Identity{Provider: provider, KeyID: keyID},
		key:      bytes.Repeat([]byte{fill}, 32),
	}
}

func (w *encryptedFaultWrapper) Identity() keywrap.Identity { return w.identity }

func (w *encryptedFaultWrapper) Wrap(_ context.Context, plaintext []byte, _ keywrap.Binding) (keywrap.WrappedDEK, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.outage {
		return keywrap.WrappedDEK{}, errors.New("provider unavailable")
	}
	ciphertext, nonce, err := vaultcrypto.Encrypt(plaintext, w.key)
	if err != nil {
		return keywrap.WrappedDEK{}, err
	}
	return keywrap.WrappedDEK{Ciphertext: append(nonce, ciphertext...), KeyVersion: "1"}, nil
}

func (w *encryptedFaultWrapper) Unwrap(_ context.Context, wrapped keywrap.WrappedDEK, _ keywrap.Binding) ([]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.outage || len(wrapped.Ciphertext) < 12 {
		return nil, errors.New("provider unavailable")
	}
	plaintext, err := vaultcrypto.Decrypt(wrapped.Ciphertext[12:], wrapped.Ciphertext[:12], w.key)
	if err != nil {
		return nil, errors.New("provider unavailable")
	}
	if w.corrupt {
		plaintext[0] ^= 0xff
	}
	return plaintext, nil
}

func (w *encryptedFaultWrapper) setFault(outage, corrupt bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.outage = outage
	w.corrupt = corrupt
}

func TestFleetProviderOutageRotationAndRecoveryInvariants(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "fleet-invariants.db"))
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
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := agerecovery.New(ageIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	aws := newEncryptedFaultWrapper("aws-kms", "arn:aws:kms:us-east-1:123:key/old", 1)
	wrappers := map[string]keywrap.KeyWrapper{"aws": aws, "recovery": recovery}
	configuration := runtimeconfig.Encryption{PrimaryWrapper: "aws"}
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	unlocked, err := unlockOrSetupWithWrapperSet(cmd, db, false, configuration, wrappers)
	if err != nil {
		t.Fatal(err)
	}
	unlocked.Wipe()

	// A database snapshot contains encrypted sentinel/wrapping material but no
	// plaintext DEK. Neither provider KEK is stored in the database.
	masterRecord, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(masterRecord.DEKPlaintext) != 0 || bytes.Contains(masterRecord.Sentinel, original.Key()) ||
		bytes.Contains(masterRecord.DEKCiphertext, original.Key()) {
		t.Fatal("database master-key record exposed the DEK")
	}
	rows, err := db.ListDEKWrappings(ctx, true)
	if err != nil || len(rows) != 2 {
		t.Fatalf("wrappings = %#v, %v", rows, err)
	}
	for _, row := range rows {
		if bytes.Contains(row.WrappedDEK, original.Key()) || bytes.Equal(row.WrappedDEK, original.Key()) {
			t.Fatalf("database wrapping %s exposed the DEK", row.Provider)
		}
	}

	// Established provider outage never activates plaintext/password or age
	// fallback. The recovery wrapper rejects generic startup unwraps too.
	aws.setFault(true, false)
	if _, err := unlockOrSetupWithWrapperSet(cmd, db, false, configuration, wrappers); err == nil {
		t.Fatal("AWS outage downgraded startup protection")
	}
	if _, err := recovery.Unwrap(ctx, keywrap.WrappedDEK{}, keywrap.Binding{InstanceID: "unused"}); !errors.Is(err, agerecovery.ErrExplicitRecoveryRequired) {
		t.Fatalf("generic recovery unwrap = %v", err)
	}
	aws.setFault(false, false)

	// A partial AWS-to-Transit rotation that cannot verify its ciphertext
	// leaves AWS primary and plaintext storage absent.
	transit := newEncryptedFaultWrapper("openbao-transit", "transit/keys/replacement", 2)
	transit.setFault(false, true)
	wrappers["transit"] = transit
	configuration.PrimaryWrapper = "transit"
	if _, err := unlockOrSetupWithWrapperSet(cmd, db, false, configuration, wrappers); err == nil {
		t.Fatal("unverified Transit rotation succeeded")
	}
	primary, err := db.GetPrimaryDEKWrapping(ctx)
	if err != nil || primary.Provider != "aws-kms" {
		t.Fatalf("partial rotation changed primary = %#v, %v", primary, err)
	}
	masterRecord, _ = db.GetMasterKeyRecord(ctx)
	if len(masterRecord.DEKPlaintext) != 0 {
		t.Fatal("partial rotation restored plaintext DEK")
	}

	// Replicas with the same desired configuration converge on one verified
	// Transit primary despite concurrent random ciphertext candidates.
	transit.setFault(false, false)
	const replicas = 12
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replicaCmd := &cobra.Command{}
			replicaCmd.SetContext(ctx)
			key, err := unlockOrSetupWithWrapperSet(replicaCmd, db, false, configuration, wrappers)
			if key != nil {
				key.Wipe()
			}
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
	primary, err = db.GetPrimaryDEKWrapping(ctx)
	if err != nil || primary.Provider != "openbao-transit" || primary.KeyID != transit.Identity().KeyID {
		t.Fatalf("replicas did not converge = %#v, %v", primary, err)
	}
	binding, err := keywrap.EnsureInstanceBinding(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := keywrap.UnwrapPrimary(ctx, db, transit, binding)
	if err != nil || !bytes.Equal(dek, original.Key()) {
		t.Fatalf("rotated primary not decryptable: %x, %v", dek, err)
	}
	vaultcrypto.WipeBytes(dek)

	// With Transit unavailable, only the explicit owner-authorized age path
	// can establish a separately verified replacement primary.
	transit.setFault(true, false)
	spiffeID := "spiffe://cluster.example/ns/operators/sa/recovery"
	if _, err := db.BootstrapSPIFFEOwners(ctx, []string{spiffeID}); err != nil {
		t.Fatal(err)
	}
	actor, err := db.GetAgentBySPIFFEID(ctx, spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	replacement := newEncryptedFaultWrapper("aws-kms", "arn:aws:kms:us-east-1:123:key/recovered", 3)
	if err := performKeyRecovery(ctx, db, recovery, replacement, []byte(ageIdentity.String()), actor, spiffeID); err != nil {
		t.Fatal(err)
	}
	primary, err = db.GetPrimaryDEKWrapping(ctx)
	if err != nil || primary.KeyID != replacement.Identity().KeyID {
		t.Fatalf("recovery primary = %#v, %v", primary, err)
	}
	dek, err = keywrap.UnwrapPrimary(ctx, db, replacement, binding)
	if err != nil || !bytes.Equal(dek, original.Key()) {
		t.Fatalf("recovered primary not decryptable: %x, %v", dek, err)
	}
	vaultcrypto.WipeBytes(dek)
}
