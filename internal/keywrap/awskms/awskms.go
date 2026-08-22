package awskms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	contextInstance = "agent-vault-instance"
	contextPurpose  = "agent-vault-purpose"
	dekPurpose      = "master-dek"
)

type Client interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type Options struct {
	KeyARN string
	Region string
	Client Client
}

type Wrapper struct {
	keyARN string
	client Client
}

// New uses the AWS SDK default credential chain when no client is injected.
// This includes EKS Pod Identity, IRSA web identity, ECS, EC2, and local AWS
// profiles; no static credential fields are accepted by this API.
func New(ctx context.Context, opts Options) (*Wrapper, error) {
	parsed, err := arn.Parse(strings.TrimSpace(opts.KeyARN))
	if err != nil || parsed.Service != "kms" || parsed.Region == "" || !strings.HasPrefix(parsed.Resource, "key/") {
		return nil, errors.New("AWS KMS key ARN is invalid")
	}
	region := strings.TrimSpace(opts.Region)
	if region == "" {
		region = parsed.Region
	}
	if region != parsed.Region {
		return nil, errors.New("AWS KMS region does not match key ARN")
	}
	client := opts.Client
	if client == nil {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, errors.New("load AWS KMS identity configuration failed")
		}
		client = kms.NewFromConfig(cfg)
	}
	return &Wrapper{keyARN: parsed.String(), client: client}, nil
}

func (w *Wrapper) Identity() keywrap.Identity {
	return keywrap.Identity{Provider: "aws-kms", KeyID: w.keyARN}
}

func (w *Wrapper) Wrap(ctx context.Context, plaintext []byte, binding keywrap.Binding) (keywrap.WrappedDEK, error) {
	if err := keywrap.ValidateBinding(binding); err != nil {
		return keywrap.WrappedDEK{}, err
	}
	result, err := w.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               &w.keyARN,
		Plaintext:           plaintext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   encryptionContext(binding),
	})
	if err != nil || result == nil || len(result.CiphertextBlob) == 0 {
		return keywrap.WrappedDEK{}, errors.New("AWS KMS encrypt failed")
	}
	return keywrap.WrappedDEK{Ciphertext: append([]byte(nil), result.CiphertextBlob...)}, nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped keywrap.WrappedDEK, binding keywrap.Binding) ([]byte, error) {
	if err := keywrap.ValidateBinding(binding); err != nil {
		return nil, err
	}
	if len(wrapped.Ciphertext) == 0 {
		return nil, fmt.Errorf("AWS KMS ciphertext is required")
	}
	result, err := w.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               &w.keyARN,
		CiphertextBlob:      wrapped.Ciphertext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   encryptionContext(binding),
	})
	if err != nil || result == nil || len(result.Plaintext) != 32 {
		return nil, errors.New("AWS KMS decrypt failed")
	}
	return append([]byte(nil), result.Plaintext...), nil
}

func encryptionContext(binding keywrap.Binding) map[string]string {
	return map[string]string{contextInstance: binding.InstanceID, contextPurpose: dekPurpose}
}
