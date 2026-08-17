// Package keywrap defines provider-neutral envelope-encryption contracts for
// the Agent Vault data-encryption key (DEK).
package keywrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
)

var providerName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type Identity struct {
	Provider string
	KeyID    string
}

type Binding struct {
	InstanceID string
}

type WrappedDEK struct {
	Ciphertext []byte
	KeyVersion string
}

// KeyWrapper implementations may hold live provider clients, but Identity
// must contain only stable public routing metadata. Implementations must never
// return credentials, private keys, or plaintext in WrappedDEK.
type KeyWrapper interface {
	Identity() Identity
	Wrap(ctx context.Context, plaintext []byte, binding Binding) (WrappedDEK, error)
	Unwrap(ctx context.Context, wrapped WrappedDEK, binding Binding) ([]byte, error)
}

func ValidateIdentity(identity Identity) error {
	if !providerName.MatchString(identity.Provider) {
		return fmt.Errorf("key wrapper provider must be a lowercase slug")
	}
	if strings.TrimSpace(identity.KeyID) == "" || len(identity.KeyID) > 1024 || strings.ContainsAny(identity.KeyID, "\r\n\x00") {
		return fmt.Errorf("key wrapper key ID is invalid")
	}
	return nil
}

func ValidateBinding(binding Binding) error {
	if strings.TrimSpace(binding.InstanceID) == "" || len(binding.InstanceID) > 255 || strings.ContainsAny(binding.InstanceID, "\r\n\x00") {
		return fmt.Errorf("key wrapper instance binding is invalid")
	}
	return nil
}

// WrapAndVerify performs add-before-retire verification: the provider-created
// ciphertext is immediately unwrapped and compared with the DEK before it is
// eligible for persistence. The verification plaintext is always wiped.
func WrapAndVerify(ctx context.Context, wrapper KeyWrapper, dek []byte, binding Binding) (WrappedDEK, error) {
	if wrapper == nil {
		return WrappedDEK{}, errors.New("key wrapper is required")
	}
	if len(dek) != 32 {
		return WrappedDEK{}, fmt.Errorf("DEK must be 32 bytes")
	}
	if err := ValidateIdentity(wrapper.Identity()); err != nil {
		return WrappedDEK{}, err
	}
	if err := ValidateBinding(binding); err != nil {
		return WrappedDEK{}, err
	}
	wrapped, err := wrapper.Wrap(ctx, dek, binding)
	if err != nil {
		return WrappedDEK{}, fmt.Errorf("wrap DEK with %s: %w", wrapper.Identity().Provider, err)
	}
	if len(wrapped.Ciphertext) == 0 || len(wrapped.Ciphertext) > 1<<20 || len(wrapped.KeyVersion) > 255 || strings.ContainsAny(wrapped.KeyVersion, "\r\n\x00") {
		return WrappedDEK{}, fmt.Errorf("key wrapper returned invalid public wrapping data")
	}
	unwrapped, err := wrapper.Unwrap(ctx, wrapped, binding)
	if err != nil {
		return WrappedDEK{}, fmt.Errorf("verify wrapped DEK with %s: %w", wrapper.Identity().Provider, err)
	}
	defer vaultcrypto.WipeBytes(unwrapped)
	if len(unwrapped) != len(dek) || subtle.ConstantTimeCompare(unwrapped, dek) != 1 {
		return WrappedDEK{}, fmt.Errorf("key wrapper verification mismatch")
	}
	wrapped.Ciphertext = append([]byte(nil), wrapped.Ciphertext...)
	return wrapped, nil
}
