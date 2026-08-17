// Package contracttest contains provider-neutral conformance checks used by
// every concrete secret provider.
package contracttest

import (
	"context"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/secretprovider"
)

func RequireCancellation(t *testing.T, provider secretprovider.SecretProvider, validReference string) {
	t.Helper()
	registry := secretprovider.NewRegistry()
	if err := registry.Register("contract-provider", provider); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Fetch(ctx, "contract-provider", validReference); !errors.Is(err, context.Canceled) {
		t.Fatalf("provider cancellation = %v, want context.Canceled", err)
	}
}
