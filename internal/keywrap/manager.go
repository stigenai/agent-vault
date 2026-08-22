package keywrap

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

const instanceBindingSetting = "encryption.instance_id"

func EnsureInstanceBinding(ctx context.Context, persistence store.KeyWrappingStore) (Binding, error) {
	candidateBytes := make([]byte, 16)
	if _, err := rand.Read(candidateBytes); err != nil {
		return Binding{}, fmt.Errorf("generate encryption instance ID: %w", err)
	}
	candidate := hex.EncodeToString(candidateBytes)
	instanceID, err := persistence.GetOrCreateSetting(ctx, instanceBindingSetting, candidate)
	if err != nil {
		return Binding{}, err
	}
	binding := Binding{InstanceID: instanceID}
	if err := ValidateBinding(binding); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// EnsurePrimary converges replicas on the configured wrapper. Candidate
// ciphertext is add-before-retire verified, persisted as active, verified once
// more from persistence, then atomically promoted. Existing password wrapping
// remains as a rolling-version compatibility path; plaintext legacy storage is
// cleared in the promotion transaction.
func EnsurePrimary(ctx context.Context, persistence store.KeyWrappingStore, wrapper KeyWrapper, dek []byte, binding Binding) (*store.DEKWrappingRecord, error) {
	return ensurePrimary(ctx, persistence, wrapper, dek, binding, func(record *store.DEKWrappingRecord) error {
		return persistence.PromoteDEKWrapping(ctx, record.ID, true)
	})
}

// EnsureRecoveryPrimary follows the same verified add-before-retire workflow,
// but commits promotion together with a secret-free recovery audit record.
func EnsureRecoveryPrimary(ctx context.Context, persistence store.KeyRecoveryStore, wrapper KeyWrapper, dek []byte, binding Binding, event store.KeyRecoveryEvent) (*store.DEKWrappingRecord, error) {
	return ensurePrimary(ctx, persistence, wrapper, dek, binding, func(record *store.DEKWrappingRecord) error {
		return persistence.PromoteDEKWrappingWithRecoveryAudit(ctx, record.ID, event)
	})
}

func ensurePrimary(ctx context.Context, persistence store.KeyWrappingStore, wrapper KeyWrapper, dek []byte, binding Binding, promote func(*store.DEKWrappingRecord) error) (*store.DEKWrappingRecord, error) {
	wrapped, err := WrapAndVerify(ctx, wrapper, dek, binding)
	if err != nil {
		return nil, err
	}
	record := &store.DEKWrappingRecord{
		Provider: wrapper.Identity().Provider, KeyID: wrapper.Identity().KeyID,
		KeyVersion: wrapped.KeyVersion, WrappedDEK: wrapped.Ciphertext,
		Status: store.DEKWrappingActive, VerifiedAt: time.Now().UTC(),
	}
	if err := persistence.InsertDEKWrapping(ctx, record); err != nil {
		record, err = findWrapping(ctx, persistence, wrapper.Identity(), wrapped.KeyVersion)
		if err != nil {
			return nil, fmt.Errorf("persist verified DEK wrapping: %w", err)
		}
	}
	if err := verifyPersisted(ctx, wrapper, record, dek, binding); err != nil {
		return nil, err
	}
	if err := promote(record); err != nil {
		return nil, err
	}
	primary, err := persistence.GetPrimaryDEKWrapping(ctx)
	if err != nil {
		return nil, err
	}
	if primary.ID != record.ID {
		return nil, errors.New("configured DEK wrapping did not remain primary")
	}
	return primary, nil
}

// EnsureAdditional persists a non-primary wrapping. Provider-backed wrappers
// receive full unwrap verification. The recovery-only age wrapper is verified
// by successful public-recipient encryption and remains impossible to unwrap
// through the generic startup path.
func EnsureAdditional(ctx context.Context, persistence store.KeyWrappingStore, wrapper KeyWrapper, dek []byte, binding Binding) (*store.DEKWrappingRecord, error) {
	var wrapped WrappedDEK
	var err error
	if wrapper.Identity().Provider == "age-x25519" {
		wrapped, err = wrapper.Wrap(ctx, dek, binding)
	} else {
		wrapped, err = WrapAndVerify(ctx, wrapper, dek, binding)
	}
	if err != nil {
		return nil, err
	}
	record := &store.DEKWrappingRecord{
		Provider: wrapper.Identity().Provider, KeyID: wrapper.Identity().KeyID,
		KeyVersion: wrapped.KeyVersion, WrappedDEK: wrapped.Ciphertext,
		Status: store.DEKWrappingActive, VerifiedAt: time.Now().UTC(),
	}
	if err := persistence.InsertDEKWrapping(ctx, record); err != nil {
		return findWrapping(ctx, persistence, wrapper.Identity(), wrapped.KeyVersion)
	}
	return record, nil
}

func UnwrapPrimary(ctx context.Context, persistence store.KeyWrappingStore, wrapper KeyWrapper, binding Binding) ([]byte, error) {
	primary, err := persistence.GetPrimaryDEKWrapping(ctx)
	if err != nil {
		return nil, err
	}
	return UnwrapRecord(ctx, primary, wrapper, binding)
}

// UnwrapRecord unwraps the exact versioned row selected by the caller. This
// avoids a second primary read racing with another replica's promotion.
func UnwrapRecord(ctx context.Context, record *store.DEKWrappingRecord, wrapper KeyWrapper, binding Binding) ([]byte, error) {
	if record == nil || wrapper == nil {
		return nil, errors.New("DEK wrapping record and wrapper are required")
	}
	if record.Provider != wrapper.Identity().Provider || record.KeyID != wrapper.Identity().KeyID {
		return nil, errors.New("persisted DEK wrapping does not match selected wrapper")
	}
	return wrapper.Unwrap(ctx, WrappedDEK{Ciphertext: record.WrappedDEK, KeyVersion: record.KeyVersion}, binding)
}

func findWrapping(ctx context.Context, persistence store.KeyWrappingStore, identity Identity, version string) (*store.DEKWrappingRecord, error) {
	records, err := persistence.ListDEKWrappings(ctx, false)
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].Provider == identity.Provider && records[i].KeyID == identity.KeyID && records[i].KeyVersion == version {
			return &records[i], nil
		}
	}
	return nil, errors.New("verified wrapping not found after concurrent insert")
}

func verifyPersisted(ctx context.Context, wrapper KeyWrapper, record *store.DEKWrappingRecord, dek []byte, binding Binding) error {
	unwrapped, err := wrapper.Unwrap(ctx, WrappedDEK{Ciphertext: record.WrappedDEK, KeyVersion: record.KeyVersion}, binding)
	if err != nil {
		return fmt.Errorf("verify persisted DEK wrapping: %w", err)
	}
	defer vaultcrypto.WipeBytes(unwrapped)
	if len(unwrapped) != len(dek) || subtle.ConstantTimeCompare(unwrapped, dek) != 1 {
		return errors.New("persisted DEK wrapping verification mismatch")
	}
	return nil
}
