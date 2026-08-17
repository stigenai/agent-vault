// Package secretprovider defines the provider-neutral contract for resolving
// live credential references. It intentionally contains no environment, file,
// stdin, inline, shell, or executable resolver; those are CLI-only import
// concerns and must never run in the server.
package secretprovider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
)

const (
	KindAWSSecretsManager = "aws-secrets-manager"
	KindOpenBaoKV2        = "openbao-kv-v2"
	KindOnePassword       = "onepassword-connect"
	KindInfisical         = "infisical"

	MaxReferenceBytes = 4096
	MaxSecretBytes    = 1 << 20
	MaxVersionBytes   = 512
)

type ErrorCode string

const (
	CodeInvalidReference ErrorCode = "invalid_reference"
	CodeProviderNotFound ErrorCode = "provider_not_found"
	CodeUnavailable      ErrorCode = "provider_unavailable"
	CodeNotFound         ErrorCode = "secret_not_found"
	CodeAccessDenied     ErrorCode = "access_denied"
	CodeInvalidResponse  ErrorCode = "invalid_response"
)

type ProviderError struct {
	code ErrorCode
}

func (e *ProviderError) Error() string {
	switch e.code {
	case CodeInvalidReference:
		return "secret reference is invalid"
	case CodeProviderNotFound:
		return "secret provider is not configured"
	case CodeNotFound:
		return "referenced secret was not found"
	case CodeAccessDenied:
		return "secret provider denied access"
	case CodeInvalidResponse:
		return "secret provider returned an invalid response"
	default:
		return "secret provider is unavailable"
	}
}

func NewError(code ErrorCode) error {
	switch code {
	case CodeInvalidReference, CodeProviderNotFound, CodeUnavailable, CodeNotFound, CodeAccessDenied, CodeInvalidResponse:
		return &ProviderError{code: code}
	default:
		return &ProviderError{code: CodeUnavailable}
	}
}

func CodeOf(err error) ErrorCode {
	var providerError *ProviderError
	if errors.As(err, &providerError) {
		return providerError.code
	}
	return CodeUnavailable
}

// Reference is implemented by provider-specific parsed reference types. Its
// canonical form is public routing metadata, never a credential value.
type Reference interface {
	ProviderKind() string
	Canonical() string
}

// SecretProvider parses only its own reference grammar and returns owned,
// wipeable secret bytes. Implementations must translate SDK/HTTP failures into
// ProviderError codes instead of returning upstream payloads or tokens.
type SecretProvider interface {
	Kind() string
	ParseReference(raw string) (Reference, error)
	Fetch(ctx context.Context, reference Reference) (Result, error)
}

// Result owns its byte slice. Callers must Wipe it as soon as the value has
// been encrypted or otherwise consumed.
type Result struct {
	value   []byte
	version string
}

func NewResult(value []byte, version string) (Result, error) {
	if value == nil || len(value) > MaxSecretBytes || !safeMetadata(version, MaxVersionBytes) {
		return Result{}, NewError(CodeInvalidResponse)
	}
	return Result{value: append([]byte(nil), value...), version: version}, nil
}

func (r *Result) Bytes() []byte {
	if r == nil {
		return nil
	}
	return r.value
}

func (r *Result) Version() string {
	if r == nil {
		return ""
	}
	return r.version
}

func (r *Result) Wipe() {
	if r == nil {
		return
	}
	vaultcrypto.WipeBytes(r.value)
	r.value = nil
	r.version = ""
}

type Registry struct {
	mu        sync.RWMutex
	providers map[string]SecretProvider
	frozen    bool
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]SecretProvider)}
}

var configuredName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func (r *Registry) Register(name string, provider SecretProvider) error {
	if r == nil {
		return errors.New("secret provider registry is nil")
	}
	if !configuredName.MatchString(name) || provider == nil || !supportedKind(provider.Kind()) {
		return errors.New("secret provider name or kind is invalid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return errors.New("secret provider registry is frozen")
	}
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("secret provider %q is already configured", name)
	}
	r.providers[name] = provider
	return nil
}

func (r *Registry) Freeze() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.frozen = true
	r.mu.Unlock()
}

func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	r.mu.RUnlock()
	sort.Strings(names)
	return names
}

func (r *Registry) Parse(providerName, raw string) (Reference, error) {
	provider, err := r.provider(providerName)
	if err != nil {
		return nil, err
	}
	if err := validateRawReference(raw); err != nil {
		return nil, err
	}
	reference, err := provider.ParseReference(raw)
	if err != nil {
		return nil, sanitizeParseError(err)
	}
	if reference == nil || reference.ProviderKind() != provider.Kind() || validateRawReference(reference.Canonical()) != nil {
		return nil, NewError(CodeInvalidReference)
	}
	return reference, nil
}

func (r *Registry) Fetch(ctx context.Context, providerName, raw string) (Result, error) {
	reference, err := r.Parse(providerName, raw)
	if err != nil {
		return Result{}, err
	}
	return r.FetchReference(ctx, providerName, reference)
}

func (r *Registry) FetchReference(ctx context.Context, providerName string, reference Reference) (Result, error) {
	provider, err := r.provider(providerName)
	if err != nil {
		return Result{}, err
	}
	if reference == nil || reference.ProviderKind() != provider.Kind() || validateRawReference(reference.Canonical()) != nil {
		return Result{}, NewError(CodeInvalidReference)
	}
	result, err := provider.Fetch(ctx, reference)
	if err != nil {
		return Result{}, sanitizeFetchError(err)
	}
	if result.value == nil || len(result.value) > MaxSecretBytes || !safeMetadata(result.version, MaxVersionBytes) {
		result.Wipe()
		return Result{}, NewError(CodeInvalidResponse)
	}
	return result, nil
}

func (r *Registry) provider(name string) (SecretProvider, error) {
	if r == nil || !configuredName.MatchString(name) {
		return nil, NewError(CodeProviderNotFound)
	}
	r.mu.RLock()
	provider := r.providers[name]
	r.mu.RUnlock()
	if provider == nil {
		return nil, NewError(CodeProviderNotFound)
	}
	return provider, nil
}

func supportedKind(kind string) bool {
	switch kind {
	case KindAWSSecretsManager, KindOpenBaoKV2, KindOnePassword, KindInfisical:
		return true
	default:
		return false
	}
}

func validateRawReference(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw || !safeMetadata(raw, MaxReferenceBytes) {
		return NewError(CodeInvalidReference)
	}
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"env:", "file:", "stdin:", "exec:", "shell:", "inline:", "literal:", "command:"} {
		if strings.HasPrefix(lower, prefix) {
			return NewError(CodeInvalidReference)
		}
	}
	return nil
}

func safeMetadata(value string, max int) bool {
	return len(value) <= max && !strings.ContainsAny(value, "\r\n\x00")
}

func sanitizeParseError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var providerError *ProviderError
	if errors.As(err, &providerError) && providerError.code == CodeInvalidReference {
		return providerError
	}
	return NewError(CodeInvalidReference)
}

func sanitizeFetchError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var providerError *ProviderError
	if errors.As(err, &providerError) {
		return providerError
	}
	return NewError(CodeUnavailable)
}
