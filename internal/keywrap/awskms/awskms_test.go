package awskms

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const testKeyARN = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"

type fakeKMS struct {
	plaintext      []byte
	context        map[string]string
	encryptContext map[string]string
	keyID          string
	err            error
}

func (f *fakeKMS) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.context, f.keyID = input.EncryptionContext, *input.KeyId
	f.encryptContext = cloneContext(input.EncryptionContext)
	f.plaintext = append([]byte(nil), input.Plaintext...)
	if f.err != nil {
		return nil, f.err
	}
	return &kms.EncryptOutput{CiphertextBlob: append([]byte("kms:"), input.Plaintext...)}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.context, f.keyID = input.EncryptionContext, *input.KeyId
	if f.err != nil || !bytes.HasPrefix(input.CiphertextBlob, []byte("kms:")) || !equalContext(input.EncryptionContext, f.encryptContext) {
		if f.err == nil {
			return nil, errors.New("encryption context mismatch")
		}
		return nil, f.err
	}
	return &kms.DecryptOutput{Plaintext: append([]byte(nil), input.CiphertextBlob[4:]...)}, nil
}

func TestAWSKMSWrapAndUnwrapUsesInstanceContext(t *testing.T) {
	client := &fakeKMS{}
	wrapper, err := New(context.Background(), Options{KeyARN: testKeyARN, Region: "us-east-1", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{9}, 32)
	binding := keywrap.Binding{InstanceID: "instance-public-id"}
	wrapped, err := keywrap.WrapAndVerify(context.Background(), wrapper, dek, binding)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped.Ciphertext, dek) || client.keyID != testKeyARN {
		t.Fatal("KMS wrapper did not use configured key")
	}
	if client.context[contextInstance] != binding.InstanceID || client.context[contextPurpose] != dekPurpose {
		t.Fatalf("encryption context = %#v", client.context)
	}
	if wrapper.Identity() != (keywrap.Identity{Provider: "aws-kms", KeyID: testKeyARN}) {
		t.Fatalf("identity = %#v", wrapper.Identity())
	}
}

func TestAWSKMSContextMismatchAndErrorsAreSanitized(t *testing.T) {
	client := &fakeKMS{}
	wrapper, err := New(context.Background(), Options{KeyARN: testKeyARN, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{1}, 32), keywrap.Binding{InstanceID: "one"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrapper.Unwrap(context.Background(), wrapped, keywrap.Binding{InstanceID: "two"})
	if err == nil {
		t.Fatal("encryption-context mismatch was accepted")
	}
	client.err = errors.New("provider detail containing SECRET-VALUE and request payload")
	_, err = wrapper.Unwrap(context.Background(), wrapped, keywrap.Binding{InstanceID: "one"})
	if err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Fatalf("unsanitized provider error: %v", err)
	}
}

func cloneContext(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func equalContext(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func TestAWSKMSConfigurationValidation(t *testing.T) {
	for _, opts := range []Options{
		{},
		{KeyARN: "alias/not-an-arn"},
		{KeyARN: testKeyARN, Region: "eu-west-1"},
		{KeyARN: "arn:aws:kms:us-east-1:123456789012:alias/not-a-key"},
	} {
		if _, err := New(context.Background(), Options{KeyARN: opts.KeyARN, Region: opts.Region, Client: &fakeKMS{}}); err == nil {
			t.Fatalf("invalid KMS config accepted: %#v", opts)
		}
	}
}
