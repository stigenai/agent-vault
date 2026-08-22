package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
)

type fleetTestProvider struct{}
type fleetTestReference string

func (fleetTestProvider) Kind() string { return secretprovider.KindAWSSecretsManager }
func (fleetTestProvider) ParseReference(raw string) (secretprovider.Reference, error) {
	if raw == "bad-reference" {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return fleetTestReference(raw), nil
}
func (fleetTestProvider) Fetch(context.Context, secretprovider.Reference) (secretprovider.Result, error) {
	panic("fleet reference validation must not fetch")
}
func (r fleetTestReference) ProviderKind() string { return secretprovider.KindAWSSecretsManager }
func (r fleetTestReference) Canonical() string    { return string(r) }

func TestFleetApplyCreatesUpdatesAndBecomesIdempotent(t *testing.T) {
	srv, ms, token := setupFleetApplyTest(t)
	manifest := fleetApplyManifest()
	plan, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if plan.Blocked || plan.Summary.Create != 5 {
		t.Fatalf("initial plan = %#v", plan)
	}
	response := applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, digest, http.StatusOK)
	if len(response.Applied) != 5 || len(ms.managedResources) != 5 {
		t.Fatalf("response=%#v ownership=%#v", response, ms.managedResources)
	}

	converged, _ := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if converged.Blocked || converged.Summary.Noop != 5 || converged.Summary.Create != 0 {
		t.Fatalf("converged plan = %#v", converged)
	}
	applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, digest, http.StatusConflict)

	manifest.Vaults[0].Services[0].Host = "uploads.github.com"
	update, updateDigest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if update.Summary.Update != 1 || update.Summary.Noop != 4 {
		t.Fatalf("update plan = %#v", update)
	}
	applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, updateDigest, http.StatusOK)
	after, _ := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if after.Summary.Noop != 5 {
		t.Fatalf("after update = %#v", after)
	}
}

func TestFleetApplyRequiresCredentialPruneAndDeletesOnlyOwnedResources(t *testing.T) {
	srv, ms, token := setupFleetApplyTest(t)
	manifest := fleetApplyManifest()
	_, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, digest, http.StatusOK)

	empty := &fleetconfig.Manifest{SchemaVersion: 1, Manager: "platform-fleet"}
	guarded, guardedDigest := buildTestFleetPlan(t, srv, empty, fleetplan.Options{Prune: true})
	if !guarded.Blocked {
		t.Fatal("credential prune was not blocked")
	}
	applyTestFleetPlan(t, srv, token, empty, fleetplan.Options{Prune: true}, guardedDigest, http.StatusConflict)

	options := fleetplan.Options{Prune: true, PruneCredentials: true}
	prune, pruneDigest := buildTestFleetPlan(t, srv, empty, options)
	if prune.Blocked || prune.Summary.Delete != 5 {
		t.Fatalf("prune plan = %#v", prune)
	}
	applyTestFleetPlan(t, srv, token, empty, options, pruneDigest, http.StatusOK)
	if _, ok := ms.vaults["fleet-vault"]; ok || len(ms.managedResources) != 0 {
		t.Fatalf("fleet resources remain: vaults=%#v ownership=%#v", ms.vaults, ms.managedResources)
	}
	if _, ok := ms.vaults["default"]; !ok {
		t.Fatal("unmanaged default vault was pruned")
	}
}

func TestFleetReferenceValidationIsOwnerOnlyAndSanitized(t *testing.T) {
	srv, ms, token := setupFleetApplyTest(t)
	request := func(reference string) *httptest.ResponseRecorder {
		body := `{"source":"aws-production","ref":"` + reference + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/fleet/provider-reference/validate", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := request("application/github#token"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), secretprovider.KindAWSSecretsManager) {
		t.Fatalf("valid response = %d %s", rec.Code, rec.Body.String())
	}
	if rec := request("bad-reference"); rec.Code != http.StatusUnprocessableEntity || strings.Contains(rec.Body.String(), "bad-reference") {
		t.Fatalf("invalid response = %d %s", rec.Code, rec.Body.String())
	}
	ms.users["owner@test.com"].Role = "member"
	if rec := request("application/github#token"); rec.Code != http.StatusForbidden {
		t.Fatalf("member response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestFleetApplyRejectsInvalidOrUnresolvedInputBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fleetconfig.Manifest)
	}{
		{
			name: "invalid schema",
			mutate: func(manifest *fleetconfig.Manifest) {
				manifest.Agents[0].SPIFFEID = "not-a-spiffe-id"
			},
		},
		{
			name: "unresolved direct import",
			mutate: func(manifest *fleetconfig.Manifest) {
				manifest.Vaults[0].Credentials = nil
				manifest.Vaults[0].Services = nil
				manifest.Vaults[0].Imports = []fleetconfig.Import{{Name: "GITHUB_TOKEN", From: "env://GITHUB_TOKEN"}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv, ms, token := setupFleetApplyTest(t)
			manifest := fleetApplyManifest()
			test.mutate(manifest)
			digest := "sha256:reviewed"
			if test.name == "unresolved direct import" {
				_, digest = buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
			}
			applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, digest, http.StatusUnprocessableEntity)
			if len(ms.managedResources) != 0 {
				t.Fatalf("apply mutated ownership before rejecting input: %#v", ms.managedResources)
			}
			if _, exists := ms.vaults["fleet-vault"]; exists {
				t.Fatal("apply created a vault before rejecting input")
			}
		})
	}
}

func TestFleetApplyImportsEncryptedCredentialWithoutLiveSource(t *testing.T) {
	srv, ms, token := setupFleetApplyTest(t)
	manifest := fleetApplyManifest()
	manifest.Vaults[0].Credentials = nil
	manifest.Vaults[0].Services = nil
	manifest.Vaults[0].Imports = []fleetconfig.Import{{
		Name: "GITHUB_TOKEN", Source: "cli-only-aws", Reference: "application/import-once",
		ProviderKind: secretprovider.KindAWSSecretsManager,
	}}
	_, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	secretValue := []byte("imported-secret-that-must-not-leak")
	response := applyTestFleetPlanWithImports(t, srv, token, manifest, digest, []fleetResolvedImport{{
		Vault: "fleet-vault", Name: "GITHUB_TOKEN", Value: secretValue,
	}}, http.StatusOK)
	if len(response.Applied) != 4 {
		t.Fatalf("response = %#v", response)
	}
	credential := ms.credentials["ns-fleet-vault:GITHUB_TOKEN"]
	if credential == nil || string(credential.Ciphertext) == string(secretValue) {
		t.Fatalf("credential was not encrypted: %#v", credential)
	}
	plaintext, err := vaultcrypto.Decrypt(credential.Ciphertext, credential.Nonce, srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	defer vaultcrypto.WipeBytes(plaintext)
	if string(plaintext) != string(secretValue) {
		t.Fatal("decrypted import does not match")
	}
	if _, exists := ms.credentialSources["ns-fleet-vault:GITHUB_TOKEN"]; exists {
		t.Fatal("one-time import retained a live source")
	}

	converged, convergedDigest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if converged.Summary.Noop != 4 {
		t.Fatalf("converged plan = %#v", converged)
	}
	idempotent := applyTestFleetPlanWithImports(t, srv, token, manifest, convergedDigest, nil, http.StatusOK)
	if len(idempotent.Applied) != 0 {
		t.Fatalf("idempotent apply mutated resources: %#v", idempotent)
	}
}

func TestFleetApplyImportUpdateDetachesExistingLiveSource(t *testing.T) {
	srv, ms, token := setupFleetApplyTest(t)
	manifest := fleetApplyManifest()
	_, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, digest, http.StatusOK)
	if _, exists := ms.credentialSources["ns-fleet-vault:GITHUB_TOKEN"]; !exists {
		t.Fatal("reference credential source was not created")
	}

	manifest.Vaults[0].Credentials = nil
	manifest.Vaults[0].Imports = []fleetconfig.Import{{Name: "GITHUB_TOKEN", From: "env://GITHUB_TOKEN"}}
	update, updateDigest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if update.Summary.Update != 1 {
		t.Fatalf("import update plan = %#v", update)
	}
	value := []byte("replacement-import")
	applyTestFleetPlanWithImports(t, srv, token, manifest, updateDigest, []fleetResolvedImport{{
		Vault: "fleet-vault", Name: "GITHUB_TOKEN", Value: value,
	}}, http.StatusOK)
	if _, exists := ms.credentialSources["ns-fleet-vault:GITHUB_TOKEN"]; exists {
		t.Fatal("import update retained the old live source")
	}
	credential := ms.credentials["ns-fleet-vault:GITHUB_TOKEN"]
	plaintext, err := vaultcrypto.Decrypt(credential.Ciphertext, credential.Nonce, srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	defer vaultcrypto.WipeBytes(plaintext)
	if string(plaintext) != string(value) {
		t.Fatal("import update did not replace the credential")
	}
}

func TestFleetApplyReportsPartialFailureAndCompensatesFailedCreate(t *testing.T) {
	srv, ms, token := setupFleetApplyTest(t)
	manifest := fleetApplyManifest()
	_, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	ms.setCredentialSourceErr = errors.New("injected source failure")

	payload, err := json.Marshal(fleetApplyRequest{
		Manifest: manifest, Options: fleetplan.Options{}, ExpectedPlanSHA256: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/fleet/apply", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "injected source failure") {
		t.Fatalf("apply leaked internal error: %s", rec.Body.String())
	}
	var failure struct {
		Error          string                `json:"error"`
		Applied        []fleetApplyResult    `json:"applied"`
		FailedResource fleetplan.ResourceRef `json:"failed_resource"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Error != "apply_failed" || len(failure.Applied) != 2 || failure.FailedResource.Kind != store.ManagedResourceCredential {
		t.Fatalf("failure response = %#v", failure)
	}
	if _, exists := ms.credentials["ns-fleet-vault:GITHUB_TOKEN"]; exists {
		t.Fatal("failed credential create left a placeholder")
	}
	credentialKey := store.ManagedResourceKey{
		Kind: store.ManagedResourceCredential, ScopeID: "ns-fleet-vault", ResourceID: "GITHUB_TOKEN",
	}
	if _, exists := ms.managedResources[credentialKey]; exists {
		t.Fatal("failed credential create left an ownership reservation")
	}
	ms.setCredentialSourceErr = nil
	recovery, recoveryDigest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if recovery.Blocked || recovery.Summary.Noop != 2 || recovery.Summary.Create != 3 {
		t.Fatalf("recovery plan = %#v", recovery)
	}
	applyTestFleetPlan(t, srv, token, manifest, fleetplan.Options{}, recoveryDigest, http.StatusOK)
	converged, _ := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if converged.Summary.Noop != 5 {
		t.Fatalf("recovered state did not converge: %#v", converged)
	}
}

func setupFleetApplyTest(t *testing.T) (*Server, *mockStore, string) {
	t.Helper()
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{ID: "root-broker", VaultID: "root-ns-id", ServicesJSON: "[]"}
	srv := newTestServer(withStore(ms))
	registry := secretprovider.NewRegistry()
	if err := registry.Register("aws-production", fleetTestProvider{}); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	srv.AttachSecretProviderRegistry(registry)
	return srv, ms, token
}

func fleetApplyManifest() *fleetconfig.Manifest {
	enabled := true
	return &fleetconfig.Manifest{
		SchemaVersion: 1, Manager: "platform-fleet",
		Agents: []fleetconfig.Agent{{
			Name: "fleet-agent", SPIFFEID: "spiffe://cluster.example/ns/agents/sa/fleet-agent", Role: "no-access",
		}},
		Vaults: []fleetconfig.Vault{{
			Name:   "fleet-vault",
			Grants: []fleetconfig.Grant{{Agent: "fleet-agent", Role: "proxy"}},
			Credentials: []fleetconfig.Credential{{
				Name: "GITHUB_TOKEN", Mode: "reference", Source: "aws-production",
				Reference: "application/github#token", ProviderKind: secretprovider.KindAWSSecretsManager,
				RefreshInterval: "5m0s", MaxStaleness: "1h0m0s",
			}},
			Services: []fleetconfig.Service{{
				Name: "github-api", Host: "api.github.com", Enabled: &enabled,
				Auth: fleetconfig.Auth{Kind: "bearer", Credential: "GITHUB_TOKEN"},
			}},
		}},
	}
}

func buildTestFleetPlan(t *testing.T, srv *Server, manifest *fleetconfig.Manifest, options fleetplan.Options) (*fleetplan.Plan, string) {
	t.Helper()
	state, err := srv.buildFleetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := fleetplan.Build(manifest, state, options)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fleetplan.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, digest
}

func applyTestFleetPlan(t *testing.T, srv *Server, token string, manifest *fleetconfig.Manifest,
	options fleetplan.Options, digest string, expectedStatus int) fleetApplyResponse {
	t.Helper()
	return applyTestFleetPlanWithOptionsAndImports(t, srv, token, manifest, options, digest, nil, expectedStatus)
}

func applyTestFleetPlanWithImports(t *testing.T, srv *Server, token string, manifest *fleetconfig.Manifest,
	digest string, imports []fleetResolvedImport, expectedStatus int) fleetApplyResponse {
	t.Helper()
	return applyTestFleetPlanWithOptionsAndImports(t, srv, token, manifest, fleetplan.Options{}, digest, imports, expectedStatus)
}

func applyTestFleetPlanWithOptionsAndImports(t *testing.T, srv *Server, token string, manifest *fleetconfig.Manifest,
	options fleetplan.Options, digest string, imports []fleetResolvedImport, expectedStatus int) fleetApplyResponse {
	t.Helper()
	payload, err := json.Marshal(fleetApplyRequest{
		Manifest: manifest, Options: options, ExpectedPlanSHA256: digest, Imports: imports,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/fleet/apply", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != expectedStatus {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, expectedStatus, rec.Body.String())
	}
	var response fleetApplyResponse
	if expectedStatus == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
	}
	return response
}
