package fleetplan

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
)

func testManifest() *fleetconfig.Manifest {
	enabled := true
	return &fleetconfig.Manifest{
		SchemaVersion: 1,
		Manager:       "platform-fleet",
		Agents: []fleetconfig.Agent{{
			Name: "pr-reviewer", SPIFFEID: "spiffe://cluster.example/ns/agents/sa/pr-reviewer", Role: "no-access",
		}},
		Vaults: []fleetconfig.Vault{{
			Name:   "github-automation",
			Grants: []fleetconfig.Grant{{Agent: "pr-reviewer", Role: "proxy"}},
			Credentials: []fleetconfig.Credential{{
				Name: "GITHUB_TOKEN", Mode: "reference", Source: "aws-production",
				Reference: "application/github#token", ProviderKind: secretprovider.KindAWSSecretsManager,
				RefreshInterval: "5m0s", MaxStaleness: "1h0m0s",
			}},
			Imports: []fleetconfig.Import{{Name: "LOCAL_TOKEN", From: "file:///very/private/token-path"}},
			Services: []fleetconfig.Service{{
				Name: "github-api", Host: "api.github.com", Enabled: &enabled,
				Auth: fleetconfig.Auth{Kind: "bearer", Credential: "GITHUB_TOKEN"},
			}},
		}},
	}
}

func TestBuildCreatesInDependencyOrderWithRedactedDetails(t *testing.T) {
	plan, err := Build(testManifest(), fleetstate.State{SchemaVersion: 1}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked || plan.Summary.Create != 6 || len(plan.Operations) != 6 {
		t.Fatalf("plan = %#v", plan)
	}
	kinds := make([]string, len(plan.Operations))
	for i, operation := range plan.Operations {
		kinds[i] = operation.Resource.Kind
		if operation.Action != ActionCreate || operation.DesiredETag == "" {
			t.Fatalf("operation = %#v", operation)
		}
	}
	expected := []string{"vault", "agent", "credential", "credential", "grant", "service"}
	if !reflect.DeepEqual(kinds, expected) {
		t.Fatalf("kinds = %#v", kinds)
	}
	service := plan.Operations[len(plan.Operations)-1]
	if !reflect.DeepEqual(service.Details.CredentialRefs, []string{"GITHUB_TOKEN"}) || len(service.Requires) != 2 {
		t.Fatalf("service = %#v", service)
	}
	local := findOperation(t, plan, store.ManagedResourceCredential, "github-automation", "LOCAL_TOKEN")
	if local.Details.Credential == nil || local.Details.Credential.Resolver != "file" || local.Details.Credential.Reference != "" {
		t.Fatalf("local import details = %#v", local.Details)
	}
}

func TestBuildIsStableAcrossEquivalentInputOrder(t *testing.T) {
	desired := testManifest()
	current := currentFromDesired(t, desired, desired.Manager)
	first, err := Build(desired, current, Options{})
	if err != nil {
		t.Fatal(err)
	}
	reversed := *desired
	reversed.Agents = append([]fleetconfig.Agent(nil), desired.Agents...)
	reversed.Vaults = append([]fleetconfig.Vault(nil), desired.Vaults...)
	for left, right := 0, len(current.Resources)-1; left < right; left, right = left+1, right-1 {
		current.Resources[left], current.Resources[right] = current.Resources[right], current.Resources[left]
	}
	second, err := Build(&reversed, current, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatalf("plans differ:\n%s\n%s", a, b)
	}
	if first.Summary.Noop != 6 {
		t.Fatalf("summary = %#v", first.Summary)
	}
}

func TestBuildRequiresExplicitAdoptionAndRejectsOtherManagers(t *testing.T) {
	desired := testManifest()
	unmanaged := currentFromDesired(t, desired, "")
	plan, err := Build(desired, unmanaged, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Blocked || plan.Summary.Conflict != 6 || len(plan.Prerequisites) != 6 {
		t.Fatalf("unmanaged plan = %#v", plan)
	}
	adopt, err := Build(desired, unmanaged, Options{Adopt: true})
	if err != nil {
		t.Fatal(err)
	}
	if adopt.Blocked || adopt.Summary.Adopt != 6 {
		t.Fatalf("adopt plan = %#v", adopt)
	}

	changed := unmanaged
	changed.Resources = append([]fleetstate.Resource(nil), unmanaged.Resources...)
	changed.Resources[0].Spec = json.RawMessage(`{"name":"changed","spiffe_id":"spiffe://cluster.example/changed","role":"no-access","status":"active"}`)
	changed.Resources[0].ETag = fleetstate.Digest(changed.Resources[0].Spec)
	adoptChanged, err := Build(desired, changed, Options{Adopt: true})
	if err != nil {
		t.Fatal(err)
	}
	if adoptChanged.Summary.AdoptUpdate != 1 || adoptChanged.Summary.Adopt != 5 {
		t.Fatalf("changed adoption = %#v", adoptChanged.Summary)
	}

	other := currentFromDesired(t, desired, "other-manager")
	conflict, err := Build(desired, other, Options{Adopt: true})
	if err != nil {
		t.Fatal(err)
	}
	if !conflict.Blocked || conflict.Summary.Conflict != 6 {
		t.Fatalf("other manager plan = %#v", conflict)
	}
}

func TestBuildPruneGuardsCredentialAndParentDeletion(t *testing.T) {
	desired := &fleetconfig.Manifest{SchemaVersion: 1, Manager: "platform-fleet"}
	current := currentFromDesired(t, testManifest(), desired.Manager)
	guarded, err := Build(desired, current, Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if !guarded.Blocked || guarded.Summary.Retain != 2 {
		t.Fatalf("guarded prune = %#v", guarded)
	}
	vault := findOperation(t, guarded, store.ManagedResourceVault, "", "github-automation")
	if vault.Action != ActionConflict || vault.Reason != "dependent_resource_retained" {
		t.Fatalf("vault deletion was not guarded: %#v", vault)
	}

	prune, err := Build(desired, current, Options{Prune: true, PruneCredentials: true})
	if err != nil {
		t.Fatal(err)
	}
	if prune.Blocked || prune.Summary.Delete != 6 {
		t.Fatalf("prune = %#v", prune)
	}
	wantOrder := []string{"service", "grant", "credential", "credential", "agent", "vault"}
	gotOrder := make([]string, len(prune.Operations))
	for i, operation := range prune.Operations {
		gotOrder[i] = operation.Resource.Kind
		if !operation.Destructive {
			t.Fatalf("delete not marked destructive: %#v", operation)
		}
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("delete order = %#v", gotOrder)
	}
	if _, err := Build(desired, current, Options{PruneCredentials: true}); err == nil {
		t.Fatal("credential prune without prune accepted")
	}
}

func TestBuildNeverIncludesImportedValuesOrLocalSelectors(t *testing.T) {
	desired := testManifest()
	desired.Vaults[0].Imports = append(desired.Vaults[0].Imports,
		fleetconfig.Import{Name: "ENV_TOKEN", From: "env://HIGHLY_SENSITIVE_ENV_NAME"})
	desired.Vaults[0].Services[0] = fleetconfig.Service{
		Name: "github-api", Host: "api.github.com",
		Auth: fleetconfig.Auth{Kind: "custom", Headers: map[string]string{
			"Authorization": "SUPER-SECRET-LITERAL {{ GITHUB_TOKEN }}",
		}},
	}
	plan, err := Build(desired, fleetstate.State{SchemaVersion: 1}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, forbidden := range []string{"/very/private/token-path", "HIGHLY_SENSITIVE_ENV_NAME", "SUPER-SECRET-LITERAL"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("plan leaked %q: %s", forbidden, output)
		}
	}
	for _, expected := range []string{"application/github#token", "aws-production", "GITHUB_TOKEN", `"resolver":"file"`, `"resolver":"env"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("plan missing safe descriptor %q: %s", expected, output)
		}
	}

	desired.Vaults[0].Credentials[0].Reference = "inline://RAW-SECRET-VALUE"
	_, err = Build(desired, fleetstate.State{SchemaVersion: 1}, Options{})
	if err == nil || strings.Contains(err.Error(), "RAW-SECRET-VALUE") {
		t.Fatalf("unsafe reference error = %v", err)
	}
}

func TestBuildRejectsMalformedCurrentState(t *testing.T) {
	desired := testManifest()
	valid := currentFromDesired(t, desired, desired.Manager)
	tests := map[string]fleetstate.State{
		"schema":    {SchemaVersion: 99},
		"etag":      cloneState(valid),
		"ownership": cloneState(valid),
		"duplicate": cloneState(valid),
	}
	tests["etag"].Resources[0].ETag = "sha256:" + strings.Repeat("0", 64)
	tests["ownership"].Resources[0].Manager = ""
	duplicate := tests["duplicate"]
	duplicate.Resources = append(duplicate.Resources, duplicate.Resources[0])
	tests["duplicate"] = duplicate
	for name, current := range tests {
		if _, err := Build(desired, current, Options{}); err == nil {
			t.Fatalf("%s state accepted", name)
		}
	}
}

func TestImportedCredentialIsIdempotentWithoutRevealingOrReapplyingSource(t *testing.T) {
	desired := testManifest()
	current := currentFromDesired(t, desired, desired.Manager)
	desired.Vaults[0].Imports[0].From = "stdin://"
	plan, err := Build(desired, current, Options{})
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, plan, store.ManagedResourceCredential, "github-automation", "LOCAL_TOKEN")
	if operation.Action != ActionNoop || operation.Details.Credential.Resolver != "stdin" {
		t.Fatalf("import operation = %#v", operation)
	}
}

func currentFromDesired(t *testing.T, desired *fleetconfig.Manifest, manager string) fleetstate.State {
	t.Helper()
	resources, err := desiredResources(desired)
	if err != nil {
		t.Fatal(err)
	}
	state := fleetstate.State{SchemaVersion: 1}
	for _, resource := range resources {
		current := resource.state
		current.Manager = manager
		if manager != "" {
			current.Revision = 3
		}
		state.Resources = append(state.Resources, current)
	}
	sort.Slice(state.Resources, func(i, j int) bool {
		left, right := state.Resources[i], state.Resources[j]
		return left.Kind+"\x00"+left.Vault+"\x00"+left.Name < right.Kind+"\x00"+right.Vault+"\x00"+right.Name
	})
	return state
}

func cloneState(state fleetstate.State) fleetstate.State {
	clone := state
	clone.Resources = append([]fleetstate.Resource(nil), state.Resources...)
	return clone
}

func findOperation(t *testing.T, plan *Plan, kind, vault, name string) Operation {
	t.Helper()
	for _, operation := range plan.Operations {
		if operation.Resource == (ResourceRef{Kind: kind, Vault: vault, Name: name}) {
			return operation
		}
	}
	t.Fatalf("operation not found: %s/%s/%s", kind, vault, name)
	return Operation{}
}
