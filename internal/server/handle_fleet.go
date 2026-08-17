package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/store"
)

type fleetResourceState = fleetstate.Resource
type fleetStateResponse = fleetstate.State

func (s *Server) handleFleetState(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	response, err := s.buildFleetState(r.Context())
	if err != nil {
		s.logger.Error("fleet state inventory failed", "error", err)
		jsonError(w, http.StatusInternalServerError, "Failed to build fleet state")
		return
	}
	jsonOK(w, response)
}

func (s *Server) buildFleetState(ctx context.Context) (fleetstate.State, error) {
	managed, err := s.store.ListManagedResources(ctx)
	if err != nil {
		return fleetstate.State{}, fmt.Errorf("listing ownership: %w", err)
	}
	ownership := make(map[store.ManagedResourceKey]store.ManagedResource, len(managed))
	for _, resource := range managed {
		ownership[resource.ManagedResourceKey] = resource
	}

	vaults, err := s.store.ListVaults(ctx)
	if err != nil {
		return fleetstate.State{}, fmt.Errorf("listing vaults: %w", err)
	}
	agents, err := s.store.ListAllAgents(ctx)
	if err != nil {
		return fleetstate.State{}, fmt.Errorf("listing agents: %w", err)
	}
	result := fleetstate.State{SchemaVersion: fleetstate.SchemaVersion}

	for _, vault := range vaults {
		if err := appendFleetResource(&result.Resources, ownership,
			store.ManagedResourceKey{Kind: store.ManagedResourceVault, ResourceID: vault.ID},
			vault.Name, "", fleetstate.VaultSpec{Name: vault.Name}); err != nil {
			return fleetstate.State{}, err
		}
		if err := s.appendVaultFleetState(ctx, &result.Resources, ownership, vault); err != nil {
			return fleetstate.State{}, err
		}
	}

	for _, agent := range agents {
		if err := appendFleetResource(&result.Resources, ownership,
			store.ManagedResourceKey{Kind: store.ManagedResourceAgent, ResourceID: agent.ID},
			agent.Name, "", fleetstate.AgentSpec{Name: agent.Name, SPIFFEID: agent.SPIFFEID, Role: agent.Role, Status: agent.Status}); err != nil {
			return fleetstate.State{}, err
		}
		for _, grant := range agent.Vaults {
			if err := appendFleetResource(&result.Resources, ownership,
				store.ManagedResourceKey{Kind: store.ManagedResourceGrant, ScopeID: grant.VaultID, ResourceID: agent.ID},
				agent.Name, grant.VaultName, fleetstate.GrantSpec{Agent: agent.Name, Role: grant.Role}); err != nil {
				return fleetstate.State{}, err
			}
		}
	}

	sort.Slice(result.Resources, func(i, j int) bool {
		left, right := result.Resources[i], result.Resources[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Vault != right.Vault {
			return left.Vault < right.Vault
		}
		return left.Name < right.Name
	})
	return result, nil
}

func (s *Server) appendVaultFleetState(ctx context.Context, resources *[]fleetstate.Resource,
	ownership map[store.ManagedResourceKey]store.ManagedResource, vault store.Vault) error {
	config, err := s.store.GetBrokerConfig(ctx, vault.ID)
	if err != nil {
		return fmt.Errorf("reading broker config for vault %q: %w", vault.Name, err)
	}
	if config == nil {
		return fmt.Errorf("broker config for vault %q is missing", vault.Name)
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
		return fmt.Errorf("decoding broker config for vault %q: %w", vault.Name, err)
	}
	for _, service := range services {
		if err := appendFleetResource(resources, ownership,
			store.ManagedResourceKey{Kind: store.ManagedResourceService, ScopeID: vault.ID, ResourceID: service.Name},
			service.Name, vault.Name, fleetstate.RedactService(service)); err != nil {
			return err
		}
	}

	credentials, err := s.store.ListCredentials(ctx, vault.ID)
	if err != nil {
		return fmt.Errorf("listing credentials for vault %q: %w", vault.Name, err)
	}
	sources, err := s.store.ListCredentialSources(ctx, vault.ID)
	if err != nil {
		return fmt.Errorf("listing credential sources for vault %q: %w", vault.Name, err)
	}
	byKey := make(map[string]store.CredentialSource, len(sources))
	for _, source := range sources {
		byKey[source.CredentialKey] = source
	}
	for _, credential := range credentials {
		spec := fleetstate.CredentialSpec{Name: credential.Key, Type: credential.Type, Mode: "imported"}
		if source, ok := byKey[credential.Key]; ok {
			spec.Mode = source.Mode
			spec.ProviderKind = source.Kind
			spec.Source = source.ProviderName
			spec.Reference = source.Reference
			spec.RefreshIntervalSeconds = source.RefreshIntervalSeconds
			spec.MaxStalenessSeconds = source.MaxStalenessSeconds
		}
		if err := appendFleetResource(resources, ownership,
			store.ManagedResourceKey{Kind: store.ManagedResourceCredential, ScopeID: vault.ID, ResourceID: credential.Key},
			credential.Key, vault.Name, spec); err != nil {
			return err
		}
	}
	return nil
}

func appendFleetResource(resources *[]fleetstate.Resource, ownership map[store.ManagedResourceKey]store.ManagedResource,
	key store.ManagedResourceKey, name, vault string, spec any) error {
	state, err := fleetstate.NewResource(key.Kind, vault, name, spec)
	if err != nil {
		return err
	}
	if managed, ok := ownership[key]; ok {
		state.Manager = managed.Manager
		state.Revision = managed.Revision
	}
	*resources = append(*resources, state)
	return nil
}
