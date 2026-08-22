package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

type fleetResolvedImportPayload struct {
	Vault string `json:"vault"`
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

type fleetImportProviders interface {
	Parse(string, string) (secretprovider.Reference, error)
	Fetch(context.Context, string, secretprovider.Reference) (secretprovider.Result, error)
}

func resolveFleetImports(cmd *cobra.Command, manifest *fleetconfig.Manifest, plan *fleetplan.Plan, providers fleetImportProviders) ([]fleetResolvedImportPayload, error) {
	imports := make(map[fleetImportKey]fleetconfig.Import)
	for _, vault := range manifest.Vaults {
		for _, item := range vault.Imports {
			imports[fleetImportKey{vault: vault.Name, name: item.Name}] = item
		}
	}
	var resolved []fleetResolvedImportPayload
	for _, operation := range plan.Operations {
		if operation.Resource.Kind != store.ManagedResourceCredential ||
			(operation.Action != fleetplan.ActionCreate && operation.Action != fleetplan.ActionUpdate && operation.Action != fleetplan.ActionAdoptUpdate) {
			continue
		}
		key := fleetImportKey{vault: operation.Resource.Vault, name: operation.Resource.Name}
		item, ok := imports[key]
		if !ok {
			continue
		}
		value, err := resolveFleetImport(cmd, providers, item)
		if err != nil {
			wipeFleetImportPayloads(resolved)
			return nil, fmt.Errorf("resolve import %q in vault %q: source unavailable", item.Name, operation.Resource.Vault)
		}
		resolved = append(resolved, fleetResolvedImportPayload{
			Vault: operation.Resource.Vault, Name: operation.Resource.Name, Value: value,
		})
	}
	return resolved, nil
}

type fleetImportKey struct {
	vault string
	name  string
}

func resolveFleetImport(cmd *cobra.Command, providers fleetImportProviders, item fleetconfig.Import) ([]byte, error) {
	if item.From != "" {
		if item.From == "stdin://" {
			value, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), secretprovider.MaxSecretBytes+1))
			if err != nil || len(value) > secretprovider.MaxSecretBytes {
				vaultcrypto.WipeBytes(value)
				return nil, errors.New("stdin import unavailable")
			}
			if value == nil {
				value = []byte{}
			}
			return value, nil
		}
		ref, err := runtimeconfig.ParseSecretRef(item.From)
		if err != nil {
			return nil, errors.New("local import source invalid")
		}
		secret, err := (runtimeconfig.Resolver{MaxBytes: secretprovider.MaxSecretBytes}).Resolve(ref)
		if err != nil {
			return nil, errors.New("local import unavailable")
		}
		defer secret.Wipe()
		value := secret.Bytes()
		if value == nil {
			value = []byte{}
		}
		return value, nil
	}
	if providers == nil || strings.TrimSpace(item.Source) == "" {
		return nil, errors.New("provider import unavailable")
	}
	reference, err := providers.Parse(item.Source, item.Reference)
	if err != nil {
		return nil, errors.New("provider import unavailable")
	}
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	result, err := providers.Fetch(ctx, item.Source, reference)
	if err != nil {
		return nil, errors.New("provider import unavailable")
	}
	defer result.Wipe()
	value := append([]byte(nil), result.Bytes()...)
	if value == nil {
		value = []byte{}
	}
	return value, nil
}

func wipeFleetImportPayloads(imports []fleetResolvedImportPayload) {
	for i := range imports {
		vaultcrypto.WipeBytes(imports[i].Value)
		imports[i].Value = nil
	}
}
