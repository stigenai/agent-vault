package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestFleetStateIsOwnerOnlyDeterministicAndRedacted(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "broker-id", VaultID: "root-ns-id",
		ServicesJSON: `[{
			"name":"github-api","host":"api.github.com","enabled":true,
			"auth":{"type":"custom","headers":{"Authorization":"private-prefix {{ GITHUB_TOKEN }}"}}
		}]`,
	}
	ms.credentials["root-ns-id:GITHUB_TOKEN"] = &store.Credential{
		ID: "credential-id", VaultID: "root-ns-id", Key: "GITHUB_TOKEN", Type: "static",
		Ciphertext: []byte("CIPHERTEXT-SECRET"), Nonce: []byte("NONCE-SECRET"),
	}
	ms.credentialSources["root-ns-id:GITHUB_TOKEN"] = &store.CredentialSource{
		VaultID: "root-ns-id", CredentialKey: "GITHUB_TOKEN", Mode: store.CredentialSourceModeReference,
		Kind: store.CredentialSourceAWSSecretsManager, ProviderName: "aws-production",
		Reference: "application/github#token", RefreshIntervalSeconds: 300, MaxStalenessSeconds: 3600,
		ProviderVersion: "PROVIDER-VERSION-SECRET", LastErrorCode: "UPSTREAM-SECRET-ERROR",
	}
	ms.agents["pr-reviewer"] = &store.Agent{
		ID: "agent-id", Name: "pr-reviewer", SPIFFEID: "spiffe://cluster.example/ns/agents/sa/pr-reviewer",
		Role: "no-access", Status: "active",
	}
	ms.agentVaultGrants = append(ms.agentVaultGrants, store.VaultGrant{
		ActorID: "agent-id", ActorType: "agent", VaultID: "root-ns-id", VaultName: "default", Role: "proxy",
	})
	serviceKey := store.ManagedResourceKey{Kind: store.ManagedResourceService, ScopeID: "root-ns-id", ResourceID: "github-api"}
	ms.managedResources[serviceKey] = store.ManagedResource{
		ManagedResourceKey: serviceKey, Manager: "platform-fleet", Revision: 7,
	}

	srv := newTestServer(withStore(ms))
	first := requestFleetState(t, srv, token)
	second := requestFleetState(t, srv, token)
	if first != second {
		t.Fatalf("fleet state is unstable:\n%s\n%s", first, second)
	}
	for _, secret := range []string{
		"CIPHERTEXT-SECRET", "NONCE-SECRET", "PROVIDER-VERSION-SECRET", "UPSTREAM-SECRET-ERROR", "private-prefix",
	} {
		if strings.Contains(first, secret) {
			t.Fatalf("fleet state leaked %q: %s", secret, first)
		}
	}

	var response fleetStateResponse
	if err := json.Unmarshal([]byte(first), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != 1 || len(response.Resources) != 5 {
		t.Fatalf("response = %#v", response)
	}
	if response.Resources[0].Kind != store.ManagedResourceAgent || response.Resources[4].Kind != store.ManagedResourceVault {
		t.Fatalf("resources are not sorted: %#v", response.Resources)
	}
	var service fleetResourceState
	for _, resource := range response.Resources {
		if resource.Kind == store.ManagedResourceService {
			service = resource
		}
		if resource.ETag == "" || !strings.HasPrefix(resource.ETag, "sha256:") {
			t.Fatalf("missing etag: %#v", resource)
		}
	}
	if service.Manager != "platform-fleet" || service.Revision != 7 {
		t.Fatalf("service ownership = %#v", service)
	}
	encodedService, err := json.Marshal(service.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encodedService), "template_sha256") || !strings.Contains(string(encodedService), "GITHUB_TOKEN") {
		t.Fatalf("redacted service spec = %s", encodedService)
	}
}

func TestFleetStateRejectsNonOwner(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.users["owner@test.com"].Role = "member"
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{ID: "broker-id", VaultID: "root-ns-id", ServicesJSON: "[]"}
	srv := newTestServer(withStore(ms))
	req := httptest.NewRequest(http.MethodGet, "/v1/fleet/state", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func requestFleetState(t *testing.T, srv *Server, token string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/fleet/state", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
