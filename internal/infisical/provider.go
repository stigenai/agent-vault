package infisical

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
	sdkerrors "github.com/infisical/go-sdk/packages/errors"
)

// Provider adapts static Infisical secrets to the common per-credential
// refresh framework. Dynamic secrets intentionally remain in DynamicResolver:
// their leased values stay memory-only and retain request-time renew/revoke
// semantics rather than becoming periodically persisted cache entries.
type Provider struct {
	fetcher      SecretRetriever
	legacyConfig *VaultConfig
}

type ProviderOptions struct {
	Fetcher SecretRetriever
	// LegacyConfig enables key-only references backfilled from the former
	// one-Infisical-store-per-vault model.
	LegacyConfig *VaultConfig
}

// Reference grammar for new sources:
//
//	project-id/environment[/secret/path]#secret-key
//
// A provider configured with LegacyConfig also accepts a key-only reference,
// matching the compatibility rows created by the credential source migration.
type ProviderReference struct {
	config    VaultConfig
	key       string
	legacy    bool
	canonical string
}

func (r ProviderReference) ProviderKind() string { return secretprovider.KindInfisical }
func (r ProviderReference) Canonical() string    { return r.canonical }

func NewProvider(options ProviderOptions) (*Provider, error) {
	if options.Fetcher == nil {
		return nil, errors.New("infisical fetcher is required")
	}
	var legacy *VaultConfig
	if options.LegacyConfig != nil {
		copy := *options.LegacyConfig
		copy.ProjectID = strings.TrimSpace(copy.ProjectID)
		copy.Environment = strings.TrimSpace(copy.Environment)
		copy.SecretPath = strings.TrimSpace(copy.SecretPath)
		if err := copy.Validate(); err != nil {
			return nil, errors.New("infisical legacy provider configuration is invalid")
		}
		legacy = &copy
	}
	return &Provider{fetcher: options.Fetcher, legacyConfig: legacy}, nil
}

func (p *Provider) Kind() string { return secretprovider.KindInfisical }

func (p *Provider) ParseReference(raw string) (secretprovider.Reference, error) {
	if p == nil || p.fetcher == nil {
		return nil, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	ref, err := parseProviderReference(raw, p.legacyConfig)
	if err != nil {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return ref, nil
}

func parseProviderReference(raw string, legacyConfig *VaultConfig) (ProviderReference, error) {
	var result ProviderReference
	base, rawKey, hasKey := strings.Cut(raw, "#")
	if !hasKey {
		if legacyConfig == nil || !validReferencePart(raw, 256) {
			return result, errors.New("invalid legacy Infisical reference")
		}
		result.config = *legacyConfig
		result.key = raw
		result.legacy = true
		result.canonical = raw
		return result, nil
	}
	if strings.Contains(rawKey, "#") {
		return result, errors.New("invalid Infisical key")
	}
	key, err := url.PathUnescape(rawKey)
	if err != nil || !validReferencePart(key, 256) {
		return result, errors.New("invalid Infisical key")
	}
	parts := strings.Split(base, "/")
	if len(parts) < 2 {
		return result, errors.New("infisical project and environment are required")
	}
	decoded := make([]string, len(parts))
	for i, part := range parts {
		value, err := url.PathUnescape(part)
		if err != nil || !validReferencePart(value, 256) {
			return result, errors.New("invalid Infisical reference path")
		}
		decoded[i] = value
	}
	result.config = VaultConfig{
		ProjectID:   decoded[0],
		Environment: decoded[1],
		SecretPath:  "/",
	}
	if len(decoded) > 2 {
		result.config.SecretPath += strings.Join(decoded[2:], "/")
	}
	if err := result.config.Validate(); err != nil {
		return ProviderReference{}, errors.New("invalid Infisical configuration")
	}
	result.key = key
	result.canonical = canonicalProviderReference(result)
	return result, nil
}

func validReferencePart(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "/?#\r\n\x00") || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func canonicalProviderReference(ref ProviderReference) string {
	parts := []string{ref.config.ProjectID, ref.config.Environment}
	path := strings.TrimPrefix(ref.config.SecretPath, "/")
	if path != "" {
		parts = append(parts, strings.Split(path, "/")...)
	}
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/") + "#" + url.PathEscape(ref.key)
}

func (p *Provider) Fetch(ctx context.Context, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := ctx.Err(); err != nil {
		return secretprovider.Result{}, err
	}
	ref, ok := reference.(ProviderReference)
	if !ok || ref.ProviderKind() != p.Kind() || ref.key == "" {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	selected, err := p.fetcher.FetchSecret(ctx, ref.config, ref.key)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return secretprovider.Result{}, err
		}
		return secretprovider.Result{}, classifyProviderError(err)
	}
	if selected.Key == "" {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeNotFound)
	}
	if selected.Key != ref.key {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	value := []byte(selected.Value)
	defer vaultcrypto.WipeBytes(value)
	return secretprovider.NewResult(value, infisicalVersion(selected))
}

func classifyProviderError(err error) error {
	var apiError *sdkerrors.APIError
	if errors.As(err, &apiError) {
		switch apiError.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return secretprovider.NewError(secretprovider.CodeAccessDenied)
		case http.StatusNotFound:
			return secretprovider.NewError(secretprovider.CodeNotFound)
		case http.StatusBadRequest:
			return secretprovider.NewError(secretprovider.CodeInvalidReference)
		}
	}
	return secretprovider.NewError(secretprovider.CodeUnavailable)
}

func infisicalVersion(secret Secret) string {
	if secret.Version <= 0 {
		return ""
	}
	version := strconv.Itoa(secret.Version)
	if secret.ID == "" || strings.ContainsAny(secret.ID, "\r\n\x00") || len(secret.ID) > 256 {
		return version
	}
	return secret.ID + ":" + version
}

type LegacyProviderStore interface {
	ListVaultCredentialStores(context.Context) ([]store.VaultCredentialStore, error)
}

// RegisterLegacyProviders makes migration-created provider names resolvable by
// the common registry. New sources can share one ordinary Provider because
// their references carry project/environment/path metadata.
func RegisterLegacyProviders(ctx context.Context, registry *secretprovider.Registry, persistence LegacyProviderStore, fetcher SecretRetriever) error {
	if registry == nil || persistence == nil || fetcher == nil {
		return errors.New("infisical legacy provider registration is invalid")
	}
	stores, err := persistence.ListVaultCredentialStores(ctx)
	if err != nil {
		return errors.New("list legacy Infisical configurations failed")
	}
	for _, credentialStore := range stores {
		if credentialStore.Kind != store.CredentialStoreInfisical {
			continue
		}
		config, err := ParseConfigJSON(credentialStore.ConfigJSON)
		if err != nil {
			return errors.New("legacy Infisical configuration is invalid")
		}
		provider, err := NewProvider(ProviderOptions{Fetcher: fetcher, LegacyConfig: &config})
		if err != nil {
			return err
		}
		if err := registry.Register(LegacyProviderName(credentialStore.VaultID), provider); err != nil {
			return err
		}
	}
	return nil
}

func LegacyProviderName(vaultID string) string { return "legacy-infisical-" + vaultID }
