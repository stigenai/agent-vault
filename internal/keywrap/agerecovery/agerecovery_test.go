package agerecovery

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"filippo.io/age"
	"github.com/Infisical/agent-vault/internal/keywrap"
)

func TestAgeRecoveryIsExplicitAndInstanceBound(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := New(identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{8}, 32)
	binding := keywrap.Binding{InstanceID: "instance-1"}
	wrapped, err := wrapper.Wrap(context.Background(), dek, binding)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped.Ciphertext, dek) || wrapped.KeyVersion != "age-v1" {
		t.Fatal("recovery wrapping contains plaintext or wrong version")
	}
	if _, err := wrapper.Unwrap(context.Background(), wrapped, binding); !errors.Is(err, ErrExplicitRecoveryRequired) {
		t.Fatalf("normal unwrap = %v", err)
	}
	recovered, err := Recover(wrapped, []byte(identity.String()), binding)
	if err != nil || !bytes.Equal(recovered, dek) {
		t.Fatalf("recover = %x, %v", recovered, err)
	}
	if _, err := Recover(wrapped, []byte(identity.String()), keywrap.Binding{InstanceID: "instance-2"}); err == nil {
		t.Fatal("cross-instance recovery was accepted")
	}
}

func TestAgeRecoveryWrongIdentityFailsWithoutFallback(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	wrong, _ := age.GenerateX25519Identity()
	wrapper, err := New(identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{3}, 32), keywrap.Binding{InstanceID: "instance"})
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), wrapped.Ciphertext...)
	if _, err := Recover(wrapped, []byte(wrong.String()), keywrap.Binding{InstanceID: "instance"}); err == nil {
		t.Fatal("wrong recovery identity succeeded")
	}
	if !bytes.Equal(before, wrapped.Ciphertext) {
		t.Fatal("failed recovery modified persisted ciphertext")
	}
	if _, err := New("AGE-SECRET-KEY-must-not-be-accepted-as-recipient"); err == nil {
		t.Fatal("private identity accepted as public recipient")
	}
}
