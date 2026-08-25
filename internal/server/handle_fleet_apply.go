package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
)

type fleetApplyRequest struct {
	Manifest           *fleetconfig.Manifest `json:"manifest"`
	Options            fleetplan.Options     `json:"options"`
	ExpectedPlanSHA256 string                `json:"expected_plan_sha256"`
	Imports            []fleetResolvedImport `json:"imports,omitempty"`
}

type fleetResolvedImport struct {
	Vault string `json:"vault"`
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

type fleetImportKey struct {
	Vault string
	Name  string
}

type fleetApplyResult struct {
	Resource fleetplan.ResourceRef `json:"resource"`
	Action   string                `json:"action"`
	Status   string                `json:"status"`
}

type fleetApplyResponse struct {
	PlanSHA256 string             `json:"plan_sha256"`
	Applied    []fleetApplyResult `json:"applied"`
}

func (s *Server) handleFleetProviderReferenceValidate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	var request struct {
		Source    string `json:"source"`
		Reference string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Source == "" || request.Reference == "" {
		jsonError(w, http.StatusBadRequest, "Invalid provider reference request")
		return
	}
	if s.secretProviders == nil {
		jsonError(w, http.StatusUnprocessableEntity, "Secret provider is not configured")
		return
	}
	reference, err := s.secretProviders.Parse(request.Source, request.Reference)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "Provider reference is invalid")
		return
	}
	jsonOK(w, map[string]string{"kind": reference.ProviderKind(), "canonical": reference.Canonical()})
}

func (s *Server) handleFleetApply(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	var request fleetApplyRequest
	defer func() {
		for i := range request.Imports {
			vaultcrypto.WipeBytes(request.Imports[i].Value)
		}
	}()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Manifest == nil || request.ExpectedPlanSHA256 == "" {
		jsonError(w, http.StatusBadRequest, "Invalid fleet apply request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "Invalid fleet apply request")
		return
	}
	manifest, err := fleetconfig.ValidateManifest(*request.Manifest, fleetconfig.LoadOptions{
		Providers: s.secretProviders, ImportProviders: fleetTransportImportProviders{manifest: request.Manifest},
	})
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "Fleet manifest is invalid")
		return
	}
	current, err := s.buildFleetState(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to build fleet state")
		return
	}
	plan, err := fleetplan.Build(manifest, current, request.Options)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "Fleet manifest is invalid")
		return
	}
	digest, err := fleetplan.Digest(plan)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to encode fleet plan")
		return
	}
	if plan.Blocked || digest != request.ExpectedPlanSHA256 {
		if s.metrics != nil {
			s.metrics.RecordFleetApply("conflict")
		}
		s.logger.Warn("fleet reconcile rejected",
			"event", "fleet_reconcile", "outcome", "conflict",
			"planned_conflicts", plan.Summary.Conflict)
		jsonStatus(w, http.StatusConflict, map[string]any{
			"error": "Fleet plan changed or has unmet prerequisites", "plan_sha256": digest, "plan": plan,
		})
		return
	}
	imports, err := validateResolvedFleetImports(manifest, plan, request.Imports)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "Fleet credential imports are invalid")
		return
	}

	response := fleetApplyResponse{PlanSHA256: digest}
	for _, operation := range plan.Operations {
		if operation.Action == fleetplan.ActionNoop || operation.Action == fleetplan.ActionRetain {
			continue
		}
		if err := s.applyFleetOperation(r.Context(), actor, manifest, imports, operation); err != nil {
			var conflict *store.ManagedResourceConflict
			status := http.StatusInternalServerError
			code := "apply_failed"
			if errors.As(err, &conflict) || errors.Is(err, sql.ErrNoRows) {
				status, code = http.StatusConflict, "revision_conflict"
			}
			if s.metrics != nil {
				if status == http.StatusConflict {
					s.metrics.RecordFleetApply("conflict")
				} else {
					s.metrics.RecordFleetApply("failure")
				}
			}
			s.logger.Warn("fleet reconcile failed",
				"event", "fleet_reconcile", "outcome", code,
				"applied_operations", len(response.Applied))
			jsonStatus(w, status, map[string]any{
				"error": code, "failed_resource": operation.Resource, "applied": response.Applied,
			})
			return
		}
		response.Applied = append(response.Applied, fleetApplyResult{
			Resource: operation.Resource, Action: operation.Action, Status: "applied",
		})
	}
	if s.metrics != nil {
		s.metrics.RecordFleetApply("success")
	}
	s.logger.Info("fleet reconcile complete",
		"event", "fleet_reconcile", "outcome", "success",
		"applied_operations", len(response.Applied))
	jsonOK(w, response)
}

func (s *Server) applyFleetOperation(ctx context.Context, actor *Actor, manifest *fleetconfig.Manifest, imports map[fleetImportKey][]byte, operation fleetplan.Operation) error {
	switch operation.Action {
	case fleetplan.ActionCreate:
		return s.createFleetResource(ctx, actor, manifest, imports, operation)
	case fleetplan.ActionAdopt:
		key, err := s.resolveManagedResourceKey(ctx, operation.Resource)
		if err != nil {
			return err
		}
		_, err = s.store.CompareAndSwapManagedResource(ctx, key, manifest.Manager, operation.ExpectedRevision)
		return err
	case fleetplan.ActionUpdate, fleetplan.ActionAdoptUpdate:
		key, err := s.resolveManagedResourceKey(ctx, operation.Resource)
		if err != nil {
			return err
		}
		if _, err := s.store.CompareAndSwapManagedResource(ctx, key, manifest.Manager, operation.ExpectedRevision); err != nil {
			return err
		}
		return s.mutateFleetResource(ctx, manifest, imports, operation.Resource)
	case fleetplan.ActionDelete:
		key, err := s.resolveManagedResourceKey(ctx, operation.Resource)
		if err != nil {
			return err
		}
		version, err := s.store.CompareAndSwapManagedResource(ctx, key, manifest.Manager, operation.ExpectedRevision)
		if err != nil {
			return err
		}
		if err := s.deleteFleetResource(ctx, operation.Resource); err != nil {
			return err
		}
		return s.store.ReleaseManagedResource(ctx, key, manifest.Manager, version.Revision)
	default:
		return fmt.Errorf("unsupported fleet action")
	}
}

func (s *Server) createFleetResource(ctx context.Context, actor *Actor, manifest *fleetconfig.Manifest, imports map[fleetImportKey][]byte, operation fleetplan.Operation) error {
	ref := operation.Resource
	var key store.ManagedResourceKey
	switch ref.Kind {
	case store.ManagedResourceVault:
		desired, ok := desiredVault(manifest, ref.Name)
		if !ok {
			return errors.New("desired vault missing")
		}
		vault, err := s.store.CreateVault(ctx, ref.Name)
		if err != nil {
			if existing, lookupErr := s.store.GetVault(ctx, ref.Name); lookupErr == nil && existing != nil {
				return sql.ErrNoRows
			}
			return err
		}
		if err := s.store.SetVaultSetting(
			ctx, vault.ID, settingUnmatchedHostPolicy, desired.UnmatchedHostPolicy,
		); err != nil {
			_ = s.store.DeleteVault(ctx, ref.Name)
			return err
		}
		key = store.ManagedResourceKey{Kind: ref.Kind, ResourceID: vault.ID}
		if _, err := s.store.CompareAndSwapManagedResource(ctx, key, manifest.Manager, 0); err != nil {
			_ = s.store.DeleteVault(ctx, ref.Name)
			return err
		}
		return nil
	case store.ManagedResourceAgent:
		desired, ok := desiredAgent(manifest, ref.Name)
		if !ok {
			return errors.New("desired agent missing")
		}
		agent, err := s.store.CreateAgent(ctx, desired.Name, actor.ID, desired.Role)
		if err != nil {
			if existing, lookupErr := s.store.GetAgentByName(ctx, desired.Name); lookupErr == nil && existing != nil {
				return sql.ErrNoRows
			}
			return err
		}
		if err := s.store.UpdateAgentSPIFFEID(ctx, agent.ID, desired.SPIFFEID); err != nil {
			_ = s.store.DeleteAgent(ctx, agent.ID)
			return err
		}
		key = store.ManagedResourceKey{Kind: ref.Kind, ResourceID: agent.ID}
		if _, err := s.store.CompareAndSwapManagedResource(ctx, key, manifest.Manager, 0); err != nil {
			_ = s.store.DeleteAgent(ctx, agent.ID)
			return err
		}
		return nil
	default:
		resolved, err := s.resolveManagedResourceKey(ctx, ref)
		if err != nil {
			return err
		}
		key = resolved
		owned, err := s.store.CompareAndSwapManagedResource(ctx, key, manifest.Manager, 0)
		if err != nil {
			return err
		}
		if err := s.mutateFleetResource(ctx, manifest, imports, ref); err != nil {
			_ = s.deleteFleetResource(ctx, ref)
			_ = s.store.ReleaseManagedResource(ctx, key, manifest.Manager, owned.Revision)
			return err
		}
		return nil
	}
}

func (s *Server) mutateFleetResource(ctx context.Context, manifest *fleetconfig.Manifest, imports map[fleetImportKey][]byte, ref fleetplan.ResourceRef) error {
	switch ref.Kind {
	case store.ManagedResourceVault:
		desired, ok := desiredVault(manifest, ref.Name)
		if !ok {
			return errors.New("desired vault missing")
		}
		vault, err := s.store.GetVault(ctx, ref.Name)
		if err != nil {
			return err
		}
		return s.store.SetVaultSetting(
			ctx, vault.ID, settingUnmatchedHostPolicy, desired.UnmatchedHostPolicy,
		)
	case store.ManagedResourceAgent:
		desired, ok := desiredAgent(manifest, ref.Name)
		if !ok {
			return errors.New("desired agent missing")
		}
		agent, err := s.store.GetAgentByName(ctx, ref.Name)
		if err != nil {
			return err
		}
		if err := s.store.UpdateAgentSPIFFEID(ctx, agent.ID, desired.SPIFFEID); err != nil {
			return err
		}
		return s.store.UpdateAgentRole(ctx, agent.ID, desired.Role)
	case store.ManagedResourceGrant:
		grant, ok := desiredGrant(manifest, ref.Vault, ref.Name)
		if !ok {
			return errors.New("desired grant missing")
		}
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return err
		}
		agent, err := s.store.GetAgentByName(ctx, ref.Name)
		if err != nil {
			return err
		}
		return s.store.GrantVaultRole(ctx, agent.ID, "agent", vault.ID, grant.Role)
	case store.ManagedResourceService:
		service, ok := desiredService(manifest, ref.Vault, ref.Name)
		if !ok {
			return errors.New("desired service missing")
		}
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return err
		}
		config, err := s.store.GetBrokerConfig(ctx, vault.ID)
		if err != nil {
			return err
		}
		if config == nil {
			return sql.ErrNoRows
		}
		var services []broker.Service
		if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
			return err
		}
		replacement := service.BrokerService()
		found := false
		for i := range services {
			if services[i].Name == ref.Name {
				services[i], found = replacement, true
			}
		}
		if !found {
			services = append(services, replacement)
		}
		sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
		encoded, err := json.Marshal(services)
		if err != nil {
			return err
		}
		_, err = s.store.SetBrokerConfig(ctx, vault.ID, string(encoded))
		return err
	case store.ManagedResourceCredential:
		credential, imported, ok := desiredCredential(manifest, ref.Vault, ref.Name)
		if !ok {
			return errors.New("desired credential missing")
		}
		if imported {
			value, ok := imports[fleetImportKey{Vault: ref.Vault, Name: ref.Name}]
			if !ok {
				return errors.New("credential import requires resolved value")
			}
			ciphertext, nonce, err := vaultcrypto.Encrypt(value, s.encKey)
			if err != nil {
				return errors.New("credential import encryption failed")
			}
			vault, err := s.store.GetVault(ctx, ref.Vault)
			if err != nil {
				return err
			}
			if _, err := s.store.SetCredential(ctx, vault.ID, ref.Name, ciphertext, nonce); err != nil {
				return err
			}
			return s.store.DeleteCredentialSource(ctx, vault.ID, ref.Name)
		}
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return err
		}
		if _, err := s.store.GetCredential(ctx, vault.ID, ref.Name); errors.Is(err, sql.ErrNoRows) {
			if _, err := s.store.SetCredential(ctx, vault.ID, ref.Name, []byte{}, []byte{}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		refresh, _ := time.ParseDuration(credential.RefreshInterval)
		stale, _ := time.ParseDuration(credential.MaxStaleness)
		_, err = s.store.SetCredentialSource(ctx, store.CredentialSource{
			VaultID: vault.ID, CredentialKey: credential.Name, Mode: credential.Mode,
			Kind: credential.ProviderKind, ProviderName: credential.Source, Reference: credential.Reference,
			RefreshIntervalSeconds: int(refresh / time.Second), MaxStalenessSeconds: int(stale / time.Second),
			Health: store.CredentialSourceHealthPending,
		})
		return err
	default:
		return errors.New("unsupported desired resource")
	}
}

func (s *Server) deleteFleetResource(ctx context.Context, ref fleetplan.ResourceRef) error {
	switch ref.Kind {
	case store.ManagedResourceService:
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return err
		}
		config, err := s.store.GetBrokerConfig(ctx, vault.ID)
		if err != nil {
			return err
		}
		if config == nil {
			return sql.ErrNoRows
		}
		var services []broker.Service
		if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
			return err
		}
		kept := services[:0]
		for _, service := range services {
			if service.Name != ref.Name {
				kept = append(kept, service)
			}
		}
		encoded, _ := json.Marshal(kept)
		_, err = s.store.SetBrokerConfig(ctx, vault.ID, string(encoded))
		return err
	case store.ManagedResourceGrant:
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return err
		}
		agent, err := s.store.GetAgentByName(ctx, ref.Name)
		if err != nil {
			return err
		}
		return s.store.RevokeVaultAccess(ctx, agent.ID, vault.ID)
	case store.ManagedResourceCredential:
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return err
		}
		return s.store.DeleteCredential(ctx, vault.ID, ref.Name)
	case store.ManagedResourceAgent:
		agent, err := s.store.GetAgentByName(ctx, ref.Name)
		if err != nil {
			return err
		}
		return s.store.DeleteAgent(ctx, agent.ID)
	case store.ManagedResourceVault:
		return s.store.DeleteVault(ctx, ref.Name)
	default:
		return errors.New("unsupported resource deletion")
	}
}

func (s *Server) resolveManagedResourceKey(ctx context.Context, ref fleetplan.ResourceRef) (store.ManagedResourceKey, error) {
	switch ref.Kind {
	case store.ManagedResourceVault:
		vault, err := s.store.GetVault(ctx, ref.Name)
		if err != nil {
			return store.ManagedResourceKey{}, err
		}
		return store.ManagedResourceKey{Kind: ref.Kind, ResourceID: vault.ID}, nil
	case store.ManagedResourceAgent:
		agent, err := s.store.GetAgentByName(ctx, ref.Name)
		if err != nil {
			return store.ManagedResourceKey{}, err
		}
		return store.ManagedResourceKey{Kind: ref.Kind, ResourceID: agent.ID}, nil
	case store.ManagedResourceGrant:
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return store.ManagedResourceKey{}, err
		}
		agent, err := s.store.GetAgentByName(ctx, ref.Name)
		if err != nil {
			return store.ManagedResourceKey{}, err
		}
		return store.ManagedResourceKey{Kind: ref.Kind, ScopeID: vault.ID, ResourceID: agent.ID}, nil
	case store.ManagedResourceService, store.ManagedResourceCredential:
		vault, err := s.store.GetVault(ctx, ref.Vault)
		if err != nil {
			return store.ManagedResourceKey{}, err
		}
		return store.ManagedResourceKey{Kind: ref.Kind, ScopeID: vault.ID, ResourceID: ref.Name}, nil
	default:
		return store.ManagedResourceKey{}, errors.New("unsupported resource identity")
	}
}

func desiredVault(manifest *fleetconfig.Manifest, name string) (fleetconfig.Vault, bool) {
	for _, vault := range manifest.Vaults {
		if vault.Name == name {
			return vault, true
		}
	}
	return fleetconfig.Vault{}, false
}

func desiredAgent(manifest *fleetconfig.Manifest, name string) (fleetconfig.Agent, bool) {
	for _, agent := range manifest.Agents {
		if agent.Name == name {
			return agent, true
		}
	}
	return fleetconfig.Agent{}, false
}

func desiredGrant(manifest *fleetconfig.Manifest, vaultName, agentName string) (fleetconfig.Grant, bool) {
	for _, vault := range manifest.Vaults {
		if vault.Name == vaultName {
			for _, grant := range vault.Grants {
				if grant.Agent == agentName {
					return grant, true
				}
			}
		}
	}
	return fleetconfig.Grant{}, false
}

func desiredService(manifest *fleetconfig.Manifest, vaultName, name string) (fleetconfig.Service, bool) {
	for _, vault := range manifest.Vaults {
		if vault.Name == vaultName {
			for _, service := range vault.Services {
				if service.Name == name {
					return service, true
				}
			}
		}
	}
	return fleetconfig.Service{}, false
}

func desiredCredential(manifest *fleetconfig.Manifest, vaultName, name string) (fleetconfig.Credential, bool, bool) {
	for _, vault := range manifest.Vaults {
		if vault.Name != vaultName {
			continue
		}
		for _, credential := range vault.Credentials {
			if credential.Name == name {
				return credential, false, true
			}
		}
		for _, item := range vault.Imports {
			if item.Name == name {
				return fleetconfig.Credential{}, true, true
			}
		}
	}
	return fleetconfig.Credential{}, false, false
}

func validateResolvedFleetImports(manifest *fleetconfig.Manifest, plan *fleetplan.Plan, values []fleetResolvedImport) (map[fleetImportKey][]byte, error) {
	required := make(map[fleetImportKey]struct{})
	for _, operation := range plan.Operations {
		if operation.Resource.Kind != store.ManagedResourceCredential ||
			(operation.Action != fleetplan.ActionCreate && operation.Action != fleetplan.ActionUpdate && operation.Action != fleetplan.ActionAdoptUpdate) {
			continue
		}
		if _, imported, ok := desiredCredential(manifest, operation.Resource.Vault, operation.Resource.Name); ok && imported {
			required[fleetImportKey{Vault: operation.Resource.Vault, Name: operation.Resource.Name}] = struct{}{}
		}
	}
	resolved := make(map[fleetImportKey][]byte, len(values))
	for _, item := range values {
		key := fleetImportKey{Vault: item.Vault, Name: item.Name}
		if _, ok := required[key]; !ok || item.Value == nil || len(item.Value) > secretprovider.MaxSecretBytes {
			return nil, errors.New("unexpected import value")
		}
		if _, duplicate := resolved[key]; duplicate {
			return nil, errors.New("duplicate import value")
		}
		resolved[key] = item.Value
	}
	if len(resolved) != len(required) {
		return nil, errors.New("missing import value")
	}
	return resolved, nil
}

type fleetTransportImportProviders struct {
	manifest *fleetconfig.Manifest
}

type fleetTransportImportReference struct {
	kind      string
	canonical string
}

func (r fleetTransportImportReference) ProviderKind() string { return r.kind }
func (r fleetTransportImportReference) Canonical() string    { return r.canonical }

var fleetProviderNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func (p fleetTransportImportProviders) Parse(source, reference string) (secretprovider.Reference, error) {
	if p.manifest == nil || !fleetProviderNamePattern.MatchString(source) {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	kind := ""
	for _, vault := range p.manifest.Vaults {
		for _, item := range vault.Imports {
			if item.Source != source || item.Reference != reference {
				continue
			}
			if !supportedFleetImportKind(item.ProviderKind) || kind != "" && kind != item.ProviderKind {
				return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
			}
			kind = item.ProviderKind
		}
	}
	if kind == "" {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return fleetTransportImportReference{kind: kind, canonical: reference}, nil
}

func supportedFleetImportKind(kind string) bool {
	switch kind {
	case secretprovider.KindAWSSecretsManager, secretprovider.KindOpenBaoKV2, secretprovider.KindOnePassword:
		return true
	default:
		return false
	}
}

var _ fleetconfig.ProviderReferences = fleetTransportImportProviders{}
var _ secretprovider.Reference = fleetTransportImportReference{}
