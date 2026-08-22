package keywrap

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type fakeWrapper struct {
	identity Identity
	wrong    bool
	err      error
}

func (f fakeWrapper) Identity() Identity { return f.identity }
func (f fakeWrapper) Wrap(_ context.Context, plaintext []byte, _ Binding) (WrappedDEK, error) {
	if f.err != nil {
		return WrappedDEK{}, f.err
	}
	return WrappedDEK{Ciphertext: append([]byte("wrapped:"), plaintext...), KeyVersion: "v1"}, nil
}
func (f fakeWrapper) Unwrap(_ context.Context, wrapped WrappedDEK, _ Binding) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	dek := append([]byte(nil), bytes.TrimPrefix(wrapped.Ciphertext, []byte("wrapped:"))...)
	if f.wrong {
		dek[0] ^= 1
	}
	return dek, nil
}

func TestWrapAndVerify(t *testing.T) {
	dek := bytes.Repeat([]byte{7}, 32)
	wrapper := fakeWrapper{identity: Identity{Provider: "test-kms", KeyID: "public-key-id"}}
	wrapped, err := WrapAndVerify(context.Background(), wrapper, dek, Binding{InstanceID: "instance-1"})
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.KeyVersion != "v1" || bytes.Equal(wrapped.Ciphertext, dek) {
		t.Fatalf("invalid wrapping result: %#v", wrapped)
	}
	wrapped.Ciphertext[0] ^= 1
	if dek[0] != 7 {
		t.Fatal("returned ciphertext aliases plaintext DEK")
	}
}

func TestWrapAndVerifyFailsClosed(t *testing.T) {
	dek := bytes.Repeat([]byte{1}, 32)
	for name, wrapper := range map[string]KeyWrapper{
		"invalid identity": fakeWrapper{identity: Identity{Provider: "AWS KMS", KeyID: "key"}},
		"provider error":   fakeWrapper{identity: Identity{Provider: "aws-kms", KeyID: "key"}, err: errors.New("unavailable")},
		"mismatch":         fakeWrapper{identity: Identity{Provider: "aws-kms", KeyID: "key"}, wrong: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := WrapAndVerify(context.Background(), wrapper, dek, Binding{InstanceID: "instance-1"}); err == nil {
				t.Fatal("invalid wrapping was accepted")
			}
		})
	}
	if _, err := WrapAndVerify(context.Background(), fakeWrapper{identity: Identity{Provider: "aws-kms", KeyID: "key"}}, dek, Binding{}); err == nil {
		t.Fatal("empty instance binding was accepted")
	}
}
