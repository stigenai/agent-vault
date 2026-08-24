// Package fleetplan computes deterministic, fully redacted reconciliation
// plans from validated desired state and the server's redacted current state.
package fleetplan

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/store"
)

const SchemaVersion = 1

type Options struct {
	Adopt            bool `json:"adopt"`
	Prune            bool `json:"prune"`
	PruneCredentials bool `json:"prune_credentials"`
}

type Plan struct {
	SchemaVersion int            `json:"schema_version"`
	Manager       string         `json:"manager"`
	Options       Options        `json:"options"`
	Blocked       bool           `json:"blocked"`
	Prerequisites []Prerequisite `json:"prerequisites,omitempty"`
	Operations    []Operation    `json:"operations"`
	Summary       Summary        `json:"summary"`
}

type ResourceRef struct {
	Kind  string `json:"kind"`
	Vault string `json:"vault,omitempty"`
	Name  string `json:"name"`
}

type Operation struct {
	Resource         ResourceRef   `json:"resource"`
	Action           string        `json:"action"`
	Reason           string        `json:"reason"`
	CurrentManager   string        `json:"current_manager,omitempty"`
	ExpectedRevision int64         `json:"expected_revision"`
	ExpectedETag     string        `json:"expected_etag,omitempty"`
	DesiredETag      string        `json:"desired_etag,omitempty"`
	Destructive      bool          `json:"destructive,omitempty"`
	Requires         []ResourceRef `json:"requires,omitempty"`
	Details          Details       `json:"details,omitempty"`
}

type Details struct {
	SPIFFEID       string                `json:"spiffe_id,omitempty"`
	Role           string                `json:"role,omitempty"`
	Host           string                `json:"host,omitempty"`
	AuthKind       string                `json:"auth_kind,omitempty"`
	CredentialRefs []string              `json:"credential_refs,omitempty"`
	Credential     *CredentialDescriptor `json:"credential,omitempty"`
}

type CredentialDescriptor struct {
	Mode         string `json:"mode"`
	ProviderKind string `json:"provider_kind,omitempty"`
	Source       string `json:"source,omitempty"`
	Reference    string `json:"reference,omitempty"`
	Resolver     string `json:"resolver,omitempty"`
}

type Prerequisite struct {
	Code     string      `json:"code"`
	Resource ResourceRef `json:"resource"`
}

type Summary struct {
	Create      int `json:"create"`
	Update      int `json:"update"`
	Adopt       int `json:"adopt"`
	AdoptUpdate int `json:"adopt_update"`
	Delete      int `json:"delete"`
	Noop        int `json:"noop"`
	Retain      int `json:"retain"`
	Conflict    int `json:"conflict"`
}

const (
	ActionCreate      = "create"
	ActionUpdate      = "update"
	ActionAdopt       = "adopt"
	ActionAdoptUpdate = "adopt-update"
	ActionDelete      = "delete"
	ActionNoop        = "noop"
	ActionRetain      = "retain"
	ActionConflict    = "conflict"
)

type identity struct {
	kind  string
	vault string
	name  string
}

type desiredResource struct {
	state    fleetstate.Resource
	details  Details
	requires []ResourceRef
}

var portableIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$`)

func Build(desired *fleetconfig.Manifest, current fleetstate.State, options Options) (*Plan, error) {
	if desired == nil {
		return nil, errors.New("desired fleet manifest is required")
	}
	if desired.SchemaVersion != fleetconfig.SchemaVersion || desired.Manager == "" {
		return nil, errors.New("desired fleet manifest metadata is invalid")
	}
	if options.PruneCredentials && !options.Prune {
		return nil, errors.New("credential pruning requires prune")
	}
	currentByID, err := validateCurrent(current)
	if err != nil {
		return nil, err
	}
	desiredByID, err := desiredResources(desired)
	if err != nil {
		return nil, err
	}
	plan := &Plan{SchemaVersion: SchemaVersion, Manager: desired.Manager, Options: options}

	identities := make([]identity, 0, len(currentByID)+len(desiredByID))
	seen := make(map[identity]struct{}, len(currentByID)+len(desiredByID))
	for id := range currentByID {
		seen[id] = struct{}{}
		identities = append(identities, id)
	}
	for id := range desiredByID {
		if _, ok := seen[id]; !ok {
			identities = append(identities, id)
		}
	}
	sortIdentities(identities)

	for _, id := range identities {
		want, wanted := desiredByID[id]
		have, exists := currentByID[id]
		op := operationFor(id, want, wanted, have, exists, desired.Manager, options)
		plan.Operations = append(plan.Operations, op)
		plan.count(op.Action)
		switch op.Reason {
		case "unmanaged_requires_adoption":
			plan.Blocked = true
			plan.Prerequisites = append(plan.Prerequisites, Prerequisite{Code: "enable_adoption", Resource: op.Resource})
		case "managed_by_other":
			plan.Blocked = true
			plan.Prerequisites = append(plan.Prerequisites, Prerequisite{Code: "manager_release_required", Resource: op.Resource})
		case "credential_prune_requires_explicit_flag":
			plan.Blocked = true
			plan.Prerequisites = append(plan.Prerequisites, Prerequisite{Code: "enable_credential_prune", Resource: op.Resource})
		}
	}
	protectDestructiveParents(plan)
	sortOperations(plan.Operations)
	return plan, nil
}

// Digest is the stable review/apply guard for a fully built plan.
func Digest(plan *Plan) (string, error) {
	if plan == nil {
		return "", errors.New("plan is required")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("encoding plan: %w", err)
	}
	return fleetstate.Digest(encoded), nil
}

func protectDestructiveParents(plan *Plan) {
	for i := range plan.Operations {
		parent := &plan.Operations[i]
		if parent.Action != ActionDelete || (parent.Resource.Kind != store.ManagedResourceVault && parent.Resource.Kind != store.ManagedResourceAgent) {
			continue
		}
		blocked := false
		for j := range plan.Operations {
			child := plan.Operations[j]
			if parent.Resource.Kind == store.ManagedResourceVault {
				blocked = child.Resource.Vault == parent.Resource.Name && child.Action != ActionDelete
			} else {
				blocked = child.Resource.Kind == store.ManagedResourceGrant && child.Resource.Name == parent.Resource.Name && child.Action != ActionDelete
			}
			if blocked {
				break
			}
		}
		if !blocked {
			continue
		}
		parent.Action, parent.Reason, parent.Destructive = ActionConflict, "dependent_resource_retained", false
		plan.Summary.Delete--
		plan.Summary.Conflict++
		plan.Blocked = true
		plan.Prerequisites = append(plan.Prerequisites, Prerequisite{Code: "remove_or_manage_dependents", Resource: parent.Resource})
	}
}

func operationFor(id identity, want desiredResource, wanted bool, have fleetstate.Resource, exists bool,
	manager string, options Options) Operation {
	op := Operation{Resource: resourceRef(id)}
	if wanted {
		op.DesiredETag = want.state.ETag
		op.Requires = want.requires
		op.Details = want.details
	}
	if exists {
		op.CurrentManager = have.Manager
		op.ExpectedRevision = have.Revision
		op.ExpectedETag = have.ETag
	}

	if !wanted {
		if have.Manager != manager {
			op.Action, op.Reason = ActionRetain, "not_owned_by_manager"
			if have.Manager == "" {
				op.Reason = "unmanaged_resource"
			}
			return op
		}
		if !options.Prune {
			op.Action, op.Reason = ActionRetain, "prune_disabled"
			return op
		}
		if id.kind == store.ManagedResourceCredential && !options.PruneCredentials {
			op.Action, op.Reason = ActionRetain, "credential_prune_requires_explicit_flag"
			return op
		}
		op.Action, op.Reason, op.Destructive = ActionDelete, "owned_resource_absent_from_desired", true
		return op
	}

	if !exists {
		op.Action, op.Reason = ActionCreate, "resource_absent"
		return op
	}
	if have.Manager != "" && have.Manager != manager {
		op.Action, op.Reason = ActionConflict, "managed_by_other"
		return op
	}
	if have.Manager == "" {
		if !options.Adopt {
			op.Action, op.Reason = ActionConflict, "unmanaged_requires_adoption"
			return op
		}
		if have.ETag == want.state.ETag {
			op.Action, op.Reason = ActionAdopt, "adopt_unchanged"
		} else {
			op.Action, op.Reason = ActionAdoptUpdate, "adopt_and_update"
		}
		return op
	}
	if have.ETag == want.state.ETag {
		op.Action, op.Reason = ActionNoop, "already_converged"
		return op
	}
	op.Action, op.Reason = ActionUpdate, "spec_changed"
	return op
}

func validateCurrent(current fleetstate.State) (map[identity]fleetstate.Resource, error) {
	if current.SchemaVersion != fleetstate.SchemaVersion {
		return nil, fmt.Errorf("current fleet state schema_version must be %d", fleetstate.SchemaVersion)
	}
	result := make(map[identity]fleetstate.Resource, len(current.Resources))
	for _, resource := range current.Resources {
		if !supportedKind(resource.Kind) || !portableIdentity.MatchString(resource.Name) ||
			(resource.Vault != "" && !portableIdentity.MatchString(resource.Vault)) ||
			resource.Revision < 0 || !validETag(resource.ETag) {
			return nil, errors.New("current fleet state contains an invalid resource")
		}
		if resource.Manager != "" && !portableIdentity.MatchString(resource.Manager) {
			return nil, errors.New("current fleet state contains invalid ownership metadata")
		}
		if (resource.Manager == "" && resource.Revision != 0) || (resource.Manager != "" && resource.Revision < 1) {
			return nil, errors.New("current fleet state contains invalid ownership metadata")
		}
		if fleetstate.Digest(resource.Spec) != resource.ETag {
			return nil, errors.New("current fleet state contains an invalid resource ETag")
		}
		id := identity{kind: resource.Kind, vault: resource.Vault, name: resource.Name}
		if _, duplicate := result[id]; duplicate {
			return nil, fmt.Errorf("current fleet state contains duplicate %s resource", resource.Kind)
		}
		result[id] = resource
	}
	return result, nil
}

func desiredResources(manifest *fleetconfig.Manifest) (map[identity]desiredResource, error) {
	result := make(map[identity]desiredResource)
	add := func(id identity, spec any, details Details, requires []ResourceRef) error {
		resource, err := fleetstate.NewResource(id.kind, id.vault, id.name, spec)
		if err != nil {
			return err
		}
		if _, duplicate := result[id]; duplicate {
			return fmt.Errorf("desired state contains duplicate %s resource", id.kind)
		}
		result[id] = desiredResource{state: resource, details: details, requires: requires}
		return nil
	}
	for _, vault := range manifest.Vaults {
		policy := vault.UnmatchedHostPolicy
		if policy == "" {
			policy = "passthrough"
		}
		if err := add(identity{kind: store.ManagedResourceVault, name: vault.Name},
			fleetstate.VaultSpec{
				Name:                vault.Name,
				UnmatchedHostPolicy: policy,
			}, Details{}, nil); err != nil {
			return nil, err
		}
	}
	for _, agent := range manifest.Agents {
		if err := add(identity{kind: store.ManagedResourceAgent, name: agent.Name},
			fleetstate.AgentSpec{Name: agent.Name, SPIFFEID: agent.SPIFFEID, Role: agent.Role, Status: "active"},
			Details{SPIFFEID: agent.SPIFFEID, Role: agent.Role}, nil); err != nil {
			return nil, err
		}
	}
	for _, vault := range manifest.Vaults {
		vaultRef := ResourceRef{Kind: store.ManagedResourceVault, Name: vault.Name}
		for _, credential := range vault.Credentials {
			if credential.Mode != "reference" || !safeReferenceDescriptor(credential.Source, credential.Reference) {
				return nil, fmt.Errorf("desired credential %q has invalid reference metadata", credential.Name)
			}
			refresh, refreshErr := time.ParseDuration(credential.RefreshInterval)
			stale, staleErr := time.ParseDuration(credential.MaxStaleness)
			if refreshErr != nil || staleErr != nil {
				return nil, fmt.Errorf("desired credential %q has invalid refresh policy", credential.Name)
			}
			spec := fleetstate.CredentialSpec{
				Name: credential.Name, Type: "static", Mode: credential.Mode,
				ProviderKind: credential.ProviderKind, Source: credential.Source, Reference: credential.Reference,
				RefreshIntervalSeconds: int(refresh / time.Second), MaxStalenessSeconds: int(stale / time.Second),
			}
			details := Details{Credential: &CredentialDescriptor{
				Mode: credential.Mode, ProviderKind: credential.ProviderKind,
				Source: credential.Source, Reference: credential.Reference,
			}}
			if err := add(identity{kind: store.ManagedResourceCredential, vault: vault.Name, name: credential.Name}, spec, details, []ResourceRef{vaultRef}); err != nil {
				return nil, err
			}
		}
		for _, item := range vault.Imports {
			descriptor := &CredentialDescriptor{Mode: "imported"}
			if item.From != "" {
				resolver, ok := safeImportResolver(item.From)
				if !ok {
					return nil, fmt.Errorf("desired import %q has an invalid resolver", item.Name)
				}
				descriptor.Resolver = resolver
			} else {
				if !safeReferenceDescriptor(item.Source, item.Reference) {
					return nil, fmt.Errorf("desired import %q has invalid reference metadata", item.Name)
				}
				descriptor.ProviderKind, descriptor.Source, descriptor.Reference = item.ProviderKind, item.Source, item.Reference
			}
			if err := add(identity{kind: store.ManagedResourceCredential, vault: vault.Name, name: item.Name},
				fleetstate.CredentialSpec{Name: item.Name, Type: "static", Mode: "imported"},
				Details{Credential: descriptor}, []ResourceRef{vaultRef}); err != nil {
				return nil, err
			}
		}
		for _, grant := range vault.Grants {
			if err := add(identity{kind: store.ManagedResourceGrant, vault: vault.Name, name: grant.Agent},
				fleetstate.GrantSpec{Agent: grant.Agent, Role: grant.Role}, Details{Role: grant.Role},
				[]ResourceRef{vaultRef, {Kind: store.ManagedResourceAgent, Name: grant.Agent}}); err != nil {
				return nil, err
			}
		}
		for _, service := range vault.Services {
			brokerService := service.BrokerService()
			references := brokerService.CredentialKeys()
			sort.Strings(references)
			requires := []ResourceRef{vaultRef}
			for _, key := range references {
				requires = append(requires, ResourceRef{Kind: store.ManagedResourceCredential, Vault: vault.Name, Name: key})
			}
			if err := add(identity{kind: store.ManagedResourceService, vault: vault.Name, name: service.Name},
				fleetstate.RedactService(brokerService),
				Details{Host: brokerService.MatcherPattern(), AuthKind: brokerService.Auth.Type, CredentialRefs: references},
				requires); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func safeImportResolver(source string) (string, bool) {
	for _, resolver := range []string{"env", "file", "stdin"} {
		if strings.HasPrefix(source, resolver+"://") {
			return resolver, true
		}
	}
	return "", false
}

func safeReferenceDescriptor(source, reference string) bool {
	if source == "" || reference == "" || len(source) > 256 || len(reference) > 4096 ||
		strings.TrimSpace(source) != source || strings.TrimSpace(reference) != reference ||
		strings.ContainsAny(source+reference, "\x00\r\n`") || strings.Contains(reference, "$(") {
		return false
	}
	lower := strings.ToLower(reference)
	for _, prefix := range []string{"env:", "file:", "stdin:", "inline:", "literal:", "exec:", "shell:", "command:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func supportedKind(kind string) bool {
	switch kind {
	case store.ManagedResourceVault, store.ManagedResourceAgent, store.ManagedResourceGrant,
		store.ManagedResourceService, store.ManagedResourceCredential:
		return true
	default:
		return false
	}
}

func validETag(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func resourceRef(id identity) ResourceRef {
	return ResourceRef{Kind: id.kind, Vault: id.vault, Name: id.name}
}

func sortIdentities(ids []identity) {
	sort.Slice(ids, func(i, j int) bool {
		left, right := ids[i], ids[j]
		if kindRank(left.kind) != kindRank(right.kind) {
			return kindRank(left.kind) < kindRank(right.kind)
		}
		if left.vault != right.vault {
			return left.vault < right.vault
		}
		return left.name < right.name
	})
}

func sortOperations(operations []Operation) {
	sort.SliceStable(operations, func(i, j int) bool {
		left, right := operations[i], operations[j]
		leftDelete, rightDelete := left.Action == ActionDelete, right.Action == ActionDelete
		if leftDelete != rightDelete {
			return !leftDelete
		}
		leftRank, rightRank := kindRank(left.Resource.Kind), kindRank(right.Resource.Kind)
		if leftDelete {
			leftRank, rightRank = -leftRank, -rightRank
		}
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.Resource.Vault != right.Resource.Vault {
			return left.Resource.Vault < right.Resource.Vault
		}
		return left.Resource.Name < right.Resource.Name
	})
}

func kindRank(kind string) int {
	switch kind {
	case store.ManagedResourceVault:
		return 0
	case store.ManagedResourceAgent:
		return 1
	case store.ManagedResourceCredential:
		return 2
	case store.ManagedResourceGrant:
		return 3
	case store.ManagedResourceService:
		return 4
	default:
		return 99
	}
}

func (p *Plan) count(action string) {
	switch action {
	case ActionCreate:
		p.Summary.Create++
	case ActionUpdate:
		p.Summary.Update++
	case ActionAdopt:
		p.Summary.Adopt++
	case ActionAdoptUpdate:
		p.Summary.AdoptUpdate++
	case ActionDelete:
		p.Summary.Delete++
	case ActionNoop:
		p.Summary.Noop++
	case ActionRetain:
		p.Summary.Retain++
	case ActionConflict:
		p.Summary.Conflict++
	}
}
