// Package awssecretsmanager resolves credential values from AWS Secrets
// Manager using the AWS SDK default credential chain.
package awssecretsmanager

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

// Client is the subset of the AWS Secrets Manager client used by Provider.
type Client interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type Options struct {
	// Region selects the AWS Secrets Manager region. When empty, the AWS SDK
	// resolves it from its default configuration chain.
	Region string
	Client Client
}

type Provider struct {
	client Client
	region string
}

// Reference grammar:
//
//	secret-id[?version_id=ID|version_stage=STAGE][#field]
//
// secret-id may be a name or full Secrets Manager ARN. A field is a single
// top-level JSON object key. Query and fragment values use URL escaping.
type Reference struct {
	secretID     string
	versionID    string
	versionStage string
	field        string
	canonical    string
}

func (r Reference) ProviderKind() string { return secretprovider.KindAWSSecretsManager }
func (r Reference) Canonical() string    { return r.canonical }

var (
	secretNamePattern = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)
	versionPattern    = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	fieldPattern      = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,256}$`)
)

func New(ctx context.Context, options Options) (*Provider, error) {
	region := strings.TrimSpace(options.Region)
	client := options.Client
	if client == nil {
		loadOptions := []func(*awsconfig.LoadOptions) error{}
		if region != "" {
			loadOptions = append(loadOptions, awsconfig.WithRegion(region))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
		if err != nil {
			return nil, errors.New("load AWS Secrets Manager identity configuration failed")
		}
		if cfg.Region == "" {
			return nil, errors.New("AWS Secrets Manager region is required")
		}
		region = cfg.Region
		client = secretsmanager.NewFromConfig(cfg)
	}
	return &Provider{client: client, region: region}, nil
}

func (p *Provider) Kind() string { return secretprovider.KindAWSSecretsManager }

func (p *Provider) ParseReference(raw string) (secretprovider.Reference, error) {
	if p == nil || p.client == nil {
		return nil, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	ref, err := parseReference(raw, p.region)
	if err != nil {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return ref, nil
}

func parseReference(raw, configuredRegion string) (Reference, error) {
	var result Reference
	base, fragment, hasFragment := strings.Cut(raw, "#")
	if strings.Contains(fragment, "#") {
		return result, errors.New("multiple fragments")
	}
	secretID, rawQuery, hasQuery := strings.Cut(base, "?")
	if strings.Contains(rawQuery, "?") || !validSecretID(secretID, configuredRegion) {
		return result, errors.New("invalid secret ID")
	}

	values := url.Values{}
	if hasQuery {
		var err error
		values, err = url.ParseQuery(rawQuery)
		if err != nil {
			return result, err
		}
	}
	for key, entries := range values {
		if (key != "version_id" && key != "version_stage") || len(entries) != 1 {
			return result, errors.New("unsupported reference query")
		}
	}
	result.versionID = values.Get("version_id")
	result.versionStage = values.Get("version_stage")
	if result.versionID != "" && result.versionStage != "" {
		return result, errors.New("version ID and stage are mutually exclusive")
	}
	if (result.versionID != "" && !versionPattern.MatchString(result.versionID)) ||
		(result.versionStage != "" && !versionPattern.MatchString(result.versionStage)) {
		return result, errors.New("invalid version selector")
	}
	if hasQuery && len(values) == 0 {
		return result, errors.New("empty query")
	}

	if hasFragment {
		field, err := url.PathUnescape(fragment)
		if err != nil || !fieldPattern.MatchString(field) || strings.Contains(field, "#") {
			return result, errors.New("invalid field selector")
		}
		result.field = field
	}
	result.secretID = secretID
	result.canonical = canonicalReference(result)
	return result, nil
}

func validSecretID(secretID, configuredRegion string) bool {
	if secretID == "" || strings.TrimSpace(secretID) != secretID {
		return false
	}
	if strings.HasPrefix(secretID, "arn:") {
		parsed, err := arn.Parse(secretID)
		return err == nil && parsed.Service == "secretsmanager" && parsed.Region != "" &&
			(configuredRegion == "" || parsed.Region == configuredRegion) &&
			strings.HasPrefix(parsed.Resource, "secret:") && len(parsed.Resource) > len("secret:")
	}
	return secretNamePattern.MatchString(secretID)
}

func canonicalReference(ref Reference) string {
	var builder strings.Builder
	builder.WriteString(ref.secretID)
	query := url.Values{}
	if ref.versionID != "" {
		query.Set("version_id", ref.versionID)
	}
	if ref.versionStage != "" {
		query.Set("version_stage", ref.versionStage)
	}
	if encoded := query.Encode(); encoded != "" {
		builder.WriteByte('?')
		builder.WriteString(encoded)
	}
	if ref.field != "" {
		builder.WriteByte('#')
		builder.WriteString(url.PathEscape(ref.field))
	}
	return builder.String()
}

func (p *Provider) Fetch(ctx context.Context, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := ctx.Err(); err != nil {
		return secretprovider.Result{}, err
	}
	ref, ok := reference.(Reference)
	if !ok || ref.ProviderKind() != p.Kind() || ref.secretID == "" {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(ref.secretID)}
	if ref.versionID != "" {
		input.VersionId = aws.String(ref.versionID)
	}
	if ref.versionStage != "" {
		input.VersionStage = aws.String(ref.versionStage)
	}
	output, err := p.client.GetSecretValue(ctx, input)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return secretprovider.Result{}, err
		}
		return secretprovider.Result{}, classifyError(err)
	}
	if output == nil || output.VersionId == nil || *output.VersionId == "" ||
		(output.SecretString == nil) == (output.SecretBinary == nil) {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}

	var value []byte
	if output.SecretString != nil {
		value = []byte(*output.SecretString)
		output.SecretString = nil
	} else {
		value = append([]byte(nil), output.SecretBinary...)
		vaultcrypto.WipeBytes(output.SecretBinary)
		output.SecretBinary = nil
	}
	defer vaultcrypto.WipeBytes(value)
	if ref.field != "" {
		value, err = selectJSONField(value, ref.field)
		if err != nil {
			return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeNotFound)
		}
		defer vaultcrypto.WipeBytes(value)
	}
	return secretprovider.NewResult(value, *output.VersionId)
}

func selectJSONField(value []byte, field string) ([]byte, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil {
		return nil, err
	}
	defer func() {
		for _, raw := range object {
			vaultcrypto.WipeBytes(raw)
		}
	}()
	raw, ok := object[field]
	if !ok {
		return nil, errors.New("field not found")
	}
	var stringValue string
	if err := json.Unmarshal(raw, &stringValue); err != nil {
		return nil, errors.New("field is not a string")
	}
	return []byte(stringValue), nil
}

func classifyError(err error) error {
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return secretprovider.NewError(secretprovider.CodeNotFound)
	}
	var decryptionFailure *types.DecryptionFailure
	if errors.As(err, &decryptionFailure) {
		return secretprovider.NewError(secretprovider.CodeAccessDenied)
	}
	var invalidParameter *types.InvalidParameterException
	var invalidRequest *types.InvalidRequestException
	if errors.As(err, &invalidParameter) || errors.As(err, &invalidRequest) {
		return secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code := strings.ToLower(apiError.ErrorCode())
		if strings.Contains(code, "accessdenied") || strings.Contains(code, "unauthorized") {
			return secretprovider.NewError(secretprovider.CodeAccessDenied)
		}
		if strings.Contains(code, "notfound") || strings.Contains(code, "resourcenotfound") {
			return secretprovider.NewError(secretprovider.CodeNotFound)
		}
	}
	return secretprovider.NewError(secretprovider.CodeUnavailable)
}
