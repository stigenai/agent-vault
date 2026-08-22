package secretprovider

import (
	"context"

	"github.com/Infisical/agent-vault/internal/store"
)

type SourcePersistence interface {
	SetCredentialSource(context.Context, store.CredentialSource) (*store.CredentialSource, error)
}

// ValidateAndSetSource is the only provider-facing persistence boundary. It
// resolves the configured provider by name, parses and canonicalizes the
// reference with that provider's strict grammar, checks the stored kind, and
// only then writes metadata.
func (r *Registry) ValidateAndSetSource(ctx context.Context, persistence SourcePersistence, source store.CredentialSource) (*store.CredentialSource, error) {
	reference, err := r.Parse(source.ProviderName, source.Reference)
	if err != nil {
		return nil, err
	}
	if source.Kind != reference.ProviderKind() {
		return nil, NewError(CodeInvalidReference)
	}
	source.Reference = reference.Canonical()
	return persistence.SetCredentialSource(ctx, source)
}
