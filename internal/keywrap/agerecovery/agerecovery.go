package agerecovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
)

var ErrExplicitRecoveryRequired = errors.New("age recovery identity is accepted only by an explicit recovery operation")

var envelopeMagic = []byte("agent-vault-recovery-v1\x00")

type Wrapper struct {
	recipient *age.X25519Recipient
	publicID  string
}

func New(recipientText string) (*Wrapper, error) {
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(recipientText))
	if err != nil {
		return nil, errors.New("age X25519 recovery recipient is invalid")
	}
	return &Wrapper{recipient: recipient, publicID: recipient.String()}, nil
}

func (w *Wrapper) Identity() keywrap.Identity {
	return keywrap.Identity{Provider: "age-x25519", KeyID: w.publicID}
}

func (w *Wrapper) Wrap(_ context.Context, plaintext []byte, binding keywrap.Binding) (keywrap.WrappedDEK, error) {
	if len(plaintext) != 32 {
		return keywrap.WrappedDEK{}, errors.New("DEK must be 32 bytes")
	}
	if err := keywrap.ValidateBinding(binding); err != nil {
		return keywrap.WrappedDEK{}, err
	}
	payload := makeEnvelope(plaintext, binding.InstanceID)
	defer vaultcrypto.WipeBytes(payload)
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, w.recipient)
	if err != nil {
		return keywrap.WrappedDEK{}, errors.New("encrypt age recovery wrapping failed")
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return keywrap.WrappedDEK{}, errors.New("encrypt age recovery wrapping failed")
	}
	if err := writer.Close(); err != nil {
		return keywrap.WrappedDEK{}, errors.New("finalize age recovery wrapping failed")
	}
	return keywrap.WrappedDEK{Ciphertext: ciphertext.Bytes(), KeyVersion: "age-v1"}, nil
}

// Unwrap always fails so normal startup and generic wrapper selection cannot
// silently activate recovery. Recover is the only private-identity entrypoint.
func (w *Wrapper) Unwrap(context.Context, keywrap.WrappedDEK, keywrap.Binding) ([]byte, error) {
	return nil, ErrExplicitRecoveryRequired
}

// Recover decrypts an offline envelope using identityText supplied directly by
// an operator to the explicit recovery workflow. Callers own and must wipe the
// returned DEK.
func Recover(wrapped keywrap.WrappedDEK, identityText []byte, binding keywrap.Binding) ([]byte, error) {
	if err := keywrap.ValidateBinding(binding); err != nil {
		return nil, err
	}
	if wrapped.KeyVersion != "age-v1" || len(wrapped.Ciphertext) == 0 || len(wrapped.Ciphertext) > 1<<20 {
		return nil, errors.New("age recovery wrapping metadata is invalid")
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(identityText)))
	if err != nil {
		return nil, errors.New("age recovery identity is invalid")
	}
	reader, err := age.Decrypt(bytes.NewReader(wrapped.Ciphertext), identity)
	if err != nil {
		return nil, errors.New("age recovery decrypt failed")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil || len(payload) > 4096 {
		vaultcrypto.WipeBytes(payload)
		return nil, errors.New("age recovery envelope is malformed")
	}
	defer vaultcrypto.WipeBytes(payload)
	dek, instanceID, err := parseEnvelope(payload)
	if err != nil || instanceID != binding.InstanceID {
		return nil, errors.New("age recovery envelope binding mismatch")
	}
	return append([]byte(nil), dek...), nil
}

func makeEnvelope(dek []byte, instanceID string) []byte {
	payload := make([]byte, 0, len(envelopeMagic)+2+len(instanceID)+32)
	payload = append(payload, envelopeMagic...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(instanceID)))
	payload = append(payload, length...)
	payload = append(payload, instanceID...)
	payload = append(payload, dek...)
	return payload
}

func parseEnvelope(payload []byte) ([]byte, string, error) {
	if len(payload) < len(envelopeMagic)+2+32 || !bytes.Equal(payload[:len(envelopeMagic)], envelopeMagic) {
		return nil, "", fmt.Errorf("invalid envelope")
	}
	offset := len(envelopeMagic)
	instanceLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if instanceLength == 0 || len(payload) != offset+instanceLength+32 {
		return nil, "", fmt.Errorf("invalid envelope length")
	}
	return payload[offset+instanceLength:], string(payload[offset : offset+instanceLength]), nil
}
