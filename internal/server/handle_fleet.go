package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

const fleetStateSchemaVersion = 1

type fleetResourceState struct {
	Kind     string `json:"kind"`
	Vault    string `json:"vault,omitempty"`
	Name     string `json:"name"`
	Manager  string `json:"manager,omitempty"`
	Revision int64  `json:"revision"`
	ETag     string `json:"etag"`
	Spec     any    `json:"spec"`
}

type fleetStateResponse struct {
	SchemaVersion int                  `json:"schema_version"`
	Resources     []fleetResourceState `json:"resources"`
}

type fleetAgentSpec struct {
	Name     string `json:"name"`
	SPIFFEID string `json:"spiffe_id"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type fleetGrantSpec struct {
	Agent string `json:"agent"`
	Role  string `json:"role"`
}

type fleetCredentialSpec struct {
	Name                   string `json:"name"`
	Type                   string `json:"type"`
	Mode                   string `json:"mode"`
	ProviderKind           string `json:"provider_kind,omitempty"`
	Source                 string `json:"source,omitempty"`
	Reference              string `json:"ref,omitempty"`
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds,omitempty"`
	MaxStalenessSeconds    int    `json:"max_staleness_seconds,omitempty"`
}

type fleetServiceSpec struct {
	Name          string                `json:"name"`
	Host          string                `json:"host"`
	Path          string                `json:"path,omitempty"`
	Port          *int                  `json:"port,omitempty"`
	Enabled       bool                  `json:"enabled"`
	Auth          fleetServiceAuthSpec  `json:"auth"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
}

type fleetServiceAuthSpec struct {
	Kind         string                     `json:"kind"`
	Credential   string                     `json:"credential,omitempty"`
	Username     string                     `json:"username,omitempty"`
	Password     string                     `json:"password,omitempty"`
	Header       string                     `json:"header,omitempty"`
	PrefixSHA256 string                     `json:"prefix_sha256,omitempty"`
	Headers      map[string]fleetHeaderSpec `json:"headers,omitempty"`
}

type fleetHeaderSpec struct {
	TemplateSHA256 string   `json:"template_sha256"`
	Credentials    []string `json:"credentials,omitempty"`
}

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

func (s *Server) buildFleetState(ctx context.Context) (fleetStateResponse, error) {
	managed, err := s.store.ListManagedResources(ctx)
	if err != nil {
		return fleetStateResponse{}, fmt.Errorf("listing ownership: %w", err)
	}
	ownership := make(map[store.ManagedResourceKey]store.ManagedResource, len(managed))
	for _, resource := range managed {
		ownership[resource.ManagedResourceKey] = resource
	}

	vaults, err := s.store.ListVaults(ctx)
	if err != nil {
		return fleetStateResponse{}, fmt.Errorf("listing vaults: %w", err)
	}
	agents, err := s.store.ListAllAgents(ctx)
	if err != nil {
		return fleetStateResponse{}, fmt.Errorf("listing agents: %w", err)
	}
	result := fleetStateResponse{SchemaVersion: fleetStateSchemaVersion}

	for _, vault := range vaults {
		if err := appendFleetResource(&result.Resources, ownership,
			store.ManagedResourceKey{Kind: store.ManagedResourceVault, ResourceID: vault.ID},
			vault.Name, "", struct {
				Name string `json:"name"`
			}{Name: vault.Name}); err != nil {
			return fleetStateResponse{}, err
		}
		if err := s.appendVaultFleetState(ctx, &result.Resources, ownership, vault); err != nil {
			return fleetStateResponse{}, err
		}
	}

	for _, agent := range agents {
		if err := appendFleetResource(&result.Resources, ownership,
			store.ManagedResourceKey{Kind: store.ManagedResourceAgent, ResourceID: agent.ID},
			agent.Name, "", fleetAgentSpec{Name: agent.Name, SPIFFEID: agent.SPIFFEID, Role: agent.Role, Status: agent.Status}); err != nil {
			return fleetStateResponse{}, err
		}
		for _, grant := range agent.Vaults {
			if err := appendFleetResource(&result.Resources, ownership,
				store.ManagedResourceKey{Kind: store.ManagedResourceGrant, ScopeID: grant.VaultID, ResourceID: agent.ID},
				agent.Name, grant.VaultName, fleetGrantSpec{Agent: agent.Name, Role: grant.Role}); err != nil {
				return fleetStateResponse{}, err
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

func (s *Server) appendVaultFleetState(ctx context.Context, resources *[]fleetResourceState,
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
			service.Name, vault.Name, redactFleetService(service)); err != nil {
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
		spec := fleetCredentialSpec{Name: credential.Key, Type: credential.Type, Mode: "imported"}
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

func redactFleetService(service broker.Service) fleetServiceSpec {
	auth := fleetServiceAuthSpec{
		Kind: service.Auth.Type, Username: service.Auth.Username, Password: service.Auth.Password,
		Header: service.Auth.Header,
	}
	switch service.Auth.Type {
	case "bearer":
		auth.Credential = service.Auth.Token
	case "api-key":
		auth.Credential = service.Auth.Key
	}
	if service.Auth.Prefix != "" {
		auth.PrefixSHA256 = fleetDigest([]byte(service.Auth.Prefix))
	}
	if len(service.Auth.Headers) > 0 {
		auth.Headers = make(map[string]fleetHeaderSpec, len(service.Auth.Headers))
		for name, template := range service.Auth.Headers {
			keys := (&broker.Auth{Type: "custom", Headers: map[string]string{name: template}}).CredentialKeys()
			sort.Strings(keys)
			auth.Headers[name] = fleetHeaderSpec{TemplateSHA256: fleetDigest([]byte(template)), Credentials: keys}
		}
	}
	return fleetServiceSpec{
		Name: service.Name, Host: service.Host, Path: service.Path, Port: service.Port,
		Enabled: service.IsEnabled(), Auth: auth, Substitutions: service.Substitutions,
	}
}

func appendFleetResource(resources *[]fleetResourceState, ownership map[store.ManagedResourceKey]store.ManagedResource,
	key store.ManagedResourceKey, name, vault string, spec any) error {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("encoding %s state: %w", key.Kind, err)
	}
	state := fleetResourceState{
		Kind: key.Kind, Vault: vault, Name: name, Revision: 0,
		ETag: fleetDigest(encoded), Spec: spec,
	}
	if managed, ok := ownership[key]; ok {
		state.Manager = managed.Manager
		state.Revision = managed.Revision
	}
	*resources = append(*resources, state)
	return nil
}

func fleetDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
