package secretprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type testReference struct {
	kind      string
	canonical string
}

func (r testReference) ProviderKind() string { return r.kind }
func (r testReference) Canonical() string    { return r.canonical }

type testProvider struct {
	kind  string
	label string
	err   error
}

func (p *testProvider) Kind() string { return p.kind }
func (p *testProvider) ParseReference(raw string) (Reference, error) {
	if !strings.HasPrefix(raw, "secret/") || strings.Contains(raw, "..") {
		return nil, fmt.Errorf("parser detail SECRET-REFERENCE")
	}
	return testReference{kind: p.kind, canonical: raw}, nil
}
func (p *testProvider) Fetch(_ context.Context, reference Reference) (Result, error) {
	if p.err != nil {
		return Result{}, p.err
	}
	return NewResult([]byte(p.label+":"+reference.Canonical()), "version-1")
}

func TestRegistrySelectsConfiguredNameAndReturnsWipeableOwnedValue(t *testing.T) {
	registry := NewRegistry()
	first := &testProvider{kind: KindAWSSecretsManager, label: "account-a"}
	second := &testProvider{kind: KindAWSSecretsManager, label: "account-b"}
	if err := registry.Register("aws-a", first); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("aws-b", second); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	result, err := registry.Fetch(context.Background(), "aws-b", "secret/app#token")
	if err != nil {
		t.Fatal(err)
	}
	owned := result.Bytes()
	if string(owned) != "account-b:secret/app#token" || result.Version() != "version-1" {
		t.Fatalf("result = %q @ %q", owned, result.Version())
	}
	result.Wipe()
	if result.Bytes() != nil || result.Version() != "" {
		t.Fatal("result retained bytes or version after wipe")
	}
	for i, value := range owned {
		if value != 0 {
			t.Fatalf("owned byte %d not wiped", i)
		}
	}
	if err := registry.Register("late", first); err == nil {
		t.Fatal("frozen registry accepted late provider")
	}
}

func TestRegistryRejectsExecutableInlineAndMalformedReferences(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("aws", &testProvider{kind: KindAWSSecretsManager}); err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{
		"", " secret/app", "secret/app\nvalue", "env://TOKEN", "file:///secret",
		"stdin://", "exec://program", "shell:command", "inline:SECRET", "literal:value",
		"secret/../escape",
	} {
		if _, err := registry.Parse("aws", reference); CodeOf(err) != CodeInvalidReference {
			t.Fatalf("reference %q error = %v (%s)", reference, err, CodeOf(err))
		}
	}
	if _, err := registry.Parse("missing", "secret/app"); CodeOf(err) != CodeProviderNotFound {
		t.Fatalf("missing provider error = %v", err)
	}
}

func TestRegistrySanitizesProviderFailuresAndParserDetails(t *testing.T) {
	registry := NewRegistry()
	provider := &testProvider{kind: KindOpenBaoKV2, err: errors.New("upstream SECRET-TOKEN payload")}
	if err := registry.Register("bao", provider); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Parse("bao", "bad-reference"); err == nil || strings.Contains(err.Error(), "SECRET") || CodeOf(err) != CodeInvalidReference {
		t.Fatalf("parser error leaked = %v", err)
	}
	if _, err := registry.Fetch(context.Background(), "bao", "secret/app"); err == nil || strings.Contains(err.Error(), "SECRET") || CodeOf(err) != CodeUnavailable {
		t.Fatalf("fetch error leaked = %v", err)
	}
	provider.err = NewError(CodeAccessDenied)
	if _, err := registry.Fetch(context.Background(), "bao", "secret/app"); CodeOf(err) != CodeAccessDenied {
		t.Fatalf("typed provider error = %v", err)
	}
}

func TestNewResultCopiesInputAndRejectsInvalidMetadata(t *testing.T) {
	input := []byte("value")
	result, err := NewResult(input, "v1")
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if !bytes.Equal(result.Bytes(), []byte("value")) {
		t.Fatal("result aliased provider input")
	}
	if _, err := NewResult(nil, "v1"); CodeOf(err) != CodeInvalidResponse {
		t.Fatalf("nil result error = %v", err)
	}
	if _, err := NewResult([]byte("value"), "version\nsecret"); CodeOf(err) != CodeInvalidResponse {
		t.Fatalf("invalid version error = %v", err)
	}
}

func TestRegistryConcurrentFetchAfterFreeze(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("aws", &testProvider{kind: KindAWSSecretsManager, label: "fleet"}); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	const replicas = 32
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := registry.Fetch(context.Background(), "aws", "secret/shared")
			if err == nil {
				result.Wipe()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

type sourcePersistence struct {
	calls  int
	source store.CredentialSource
}

func (p *sourcePersistence) SetCredentialSource(_ context.Context, source store.CredentialSource) (*store.CredentialSource, error) {
	p.calls++
	p.source = source
	return &source, nil
}

func TestValidateAndSetSourceParsesBeforePersistence(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("aws-production", &testProvider{kind: KindAWSSecretsManager}); err != nil {
		t.Fatal(err)
	}
	persistence := &sourcePersistence{}
	source := store.CredentialSource{
		VaultID: "vault", CredentialKey: "TOKEN", Mode: store.CredentialSourceModeReference,
		Kind: KindAWSSecretsManager, ProviderName: "aws-production", Reference: "bad-reference",
		RefreshIntervalSeconds: 60, MaxStalenessSeconds: 300,
		Health: store.CredentialSourceHealthPending, CreatedAt: time.Now(),
	}
	if _, err := registry.ValidateAndSetSource(context.Background(), persistence, source); CodeOf(err) != CodeInvalidReference {
		t.Fatalf("invalid reference error = %v", err)
	}
	if persistence.calls != 0 {
		t.Fatal("invalid reference reached persistence")
	}
	source.Reference = "secret/app#token"
	if _, err := registry.ValidateAndSetSource(context.Background(), persistence, source); err != nil {
		t.Fatal(err)
	}
	if persistence.calls != 1 || persistence.source.Reference != "secret/app#token" {
		t.Fatalf("persisted source = %#v", persistence.source)
	}
	source.Kind = KindOpenBaoKV2
	if _, err := registry.ValidateAndSetSource(context.Background(), persistence, source); CodeOf(err) != CodeInvalidReference {
		t.Fatalf("kind mismatch error = %v", err)
	}
	if persistence.calls != 1 {
		t.Fatal("kind mismatch reached persistence")
	}
}
