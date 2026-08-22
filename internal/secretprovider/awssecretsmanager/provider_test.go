package awssecretsmanager

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/contracttest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

type fakeClient struct {
	input  *secretsmanager.GetSecretValueInput
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (f *fakeClient) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.input = input
	return f.output, f.err
}

func TestParseReferenceCanonicalizesSelectors(t *testing.T) {
	provider, err := New(context.Background(), Options{Region: "us-east-1", Client: &fakeClient{}})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Reference{
		"application/prod": {
			secretID: "application/prod", canonical: "application/prod",
		},
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:application-AbCdEf#token": {
			secretID:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:application-AbCdEf",
			field:     "token",
			canonical: "arn:aws:secretsmanager:us-east-1:123456789012:secret:application-AbCdEf#token",
		},
		"application/prod?version_stage=AWSPREVIOUS#api%20key": {
			secretID: "application/prod", versionStage: "AWSPREVIOUS", field: "api key",
			canonical: "application/prod?version_stage=AWSPREVIOUS#api%20key",
		},
		"application/prod?version_id=00000000-0000-0000-0000-000000000001": {
			secretID: "application/prod", versionID: "00000000-0000-0000-0000-000000000001",
			canonical: "application/prod?version_id=00000000-0000-0000-0000-000000000001",
		},
	}
	for raw, expected := range tests {
		reference, err := provider.ParseReference(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		got := reference.(Reference)
		if got != expected || reference.Canonical() != expected.canonical {
			t.Fatalf("parse %q = %#v, want %#v", raw, got, expected)
		}
	}
}

func TestParseReferenceRejectsAmbiguousOrUnsafeForms(t *testing.T) {
	provider, err := New(context.Background(), Options{Region: "us-east-1", Client: &fakeClient{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"",
		" application/prod",
		"application/prod?",
		"application/prod#",
		"application/prod?unknown=value",
		"application/prod?version_id=one&version_id=two",
		"application/prod?version_id=one&version_stage=AWSCURRENT",
		"application/prod#field#again",
		"arn:aws:kms:us-east-1:123456789012:key/id",
		"arn:aws:secretsmanager:eu-west-1:123456789012:secret:application-AbCdEf",
		"application/prod\nvalue",
	} {
		if _, err := provider.ParseReference(raw); secretprovider.CodeOf(err) != secretprovider.CodeInvalidReference {
			t.Fatalf("reference %q error = %v (%s)", raw, err, secretprovider.CodeOf(err))
		}
	}
}

func TestFetchStringJSONFieldAndPinnedVersion(t *testing.T) {
	client := &fakeClient{output: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"token":"SECRET-TOKEN","other":"SECRET-OTHER"}`),
		VersionId:    aws.String("version-7"),
	}}
	provider, err := New(context.Background(), Options{Region: "us-east-1", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := provider.ParseReference("application/prod?version_id=version-7#token")
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Bytes()) != "SECRET-TOKEN" || result.Version() != "version-7" {
		t.Fatalf("result = %q @ %q", result.Bytes(), result.Version())
	}
	if aws.ToString(client.input.SecretId) != "application/prod" ||
		aws.ToString(client.input.VersionId) != "version-7" || client.input.VersionStage != nil {
		t.Fatalf("input = %#v", client.input)
	}
	owned := result.Bytes()
	result.Wipe()
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("result bytes were not wiped")
	}
}

func TestFetchPreservesBinaryBytesAndVersionStage(t *testing.T) {
	want := []byte{0, 255, 1, 2, 0, 128}
	client := &fakeClient{output: &secretsmanager.GetSecretValueOutput{
		SecretBinary: append([]byte(nil), want...),
		VersionId:    aws.String("binary-version"),
	}}
	provider, err := New(context.Background(), Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := provider.ParseReference("binary/credential?version_stage=AWSPREVIOUS")
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Wipe()
	if !bytes.Equal(result.Bytes(), want) || aws.ToString(client.input.VersionStage) != "AWSPREVIOUS" {
		t.Fatalf("binary result/input mismatch: %v / %#v", result.Bytes(), client.input)
	}
	if client.output.SecretBinary != nil {
		t.Fatal("provider retained SDK response bytes")
	}
}

func TestFetchSanitizesAWSAndResponseFailures(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeClient
		field  string
		code   secretprovider.ErrorCode
	}{
		{
			name: "not found",
			client: &fakeClient{err: &types.ResourceNotFoundException{
				Message: aws.String("SECRET-NAME"),
			}},
			code: secretprovider.CodeNotFound,
		},
		{
			name: "access denied",
			client: &fakeClient{err: &smithy.GenericAPIError{
				Code: "AccessDeniedException", Message: "SECRET-POLICY",
			}},
			code: secretprovider.CodeAccessDenied,
		},
		{
			name: "KMS decryption denied",
			client: &fakeClient{err: &types.DecryptionFailure{
				Message: aws.String("SECRET-KMS-KEY"),
			}},
			code: secretprovider.CodeAccessDenied,
		},
		{
			name:   "transport",
			client: &fakeClient{err: errors.New("SECRET-ENDPOINT")},
			code:   secretprovider.CodeUnavailable,
		},
		{
			name: "missing JSON field",
			client: &fakeClient{output: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"other":"SECRET"}`), VersionId: aws.String("v1"),
			}},
			field: "#token", code: secretprovider.CodeNotFound,
		},
		{
			name: "invalid response with both representations",
			client: &fakeClient{output: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("SECRET"), SecretBinary: []byte("SECRET"), VersionId: aws.String("v1"),
			}},
			code: secretprovider.CodeInvalidResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := New(context.Background(), Options{Client: test.client})
			if err != nil {
				t.Fatal(err)
			}
			reference, err := provider.ParseReference("application/prod" + test.field)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Fetch(context.Background(), reference)
			if secretprovider.CodeOf(err) != test.code {
				t.Fatalf("error = %v (%s), want %s", err, secretprovider.CodeOf(err), test.code)
			}
			for _, secret := range []string{"SECRET-NAME", "SECRET-POLICY", "SECRET-KMS-KEY", "SECRET-ENDPOINT"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked provider detail: %v", err)
				}
			}
		})
	}
}

func TestProviderCancellationContract(t *testing.T) {
	provider, err := New(context.Background(), Options{Client: &fakeClient{output: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("SECRET"), VersionId: aws.String("v1"),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	contracttest.RequireCancellation(t, provider, "application/prod")
}
