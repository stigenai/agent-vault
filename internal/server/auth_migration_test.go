package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func (m *mockStore) InspectAuthMigration(context.Context) (store.AuthMigrationInventory, error) {
	result := store.AuthMigrationInventory{Users: len(m.users)}
	for _, agent := range m.agents {
		if agent.Status != "active" {
			continue
		}
		result.ActiveAgents++
		if agent.SPIFFEID == "" {
			result.UnboundActiveAgentNames = append(result.UnboundActiveAgentNames, agent.Name)
		}
		if agent.Role == "owner" && agent.SPIFFEID != "" {
			result.ActiveSPIFFEOwners++
		}
	}
	for _, session := range m.sessions {
		switch {
		case session.UserID != "":
			result.PersistedUserSessions++
		case session.AgentID != "":
			result.PersistedAgentSessions++
		default:
			result.PersistedScopedSessions++
		}
	}
	return result, nil
}

func (m *mockStore) RevokeLegacySessions(context.Context) (int64, error) {
	revoked := int64(len(m.sessions))
	clear(m.sessions)
	return revoked, nil
}

func TestSeededHybridMigrationPreservesSPIFFEAgentServiceAccess(t *testing.T) {
	const (
		ownerID  = "spiffe://cluster.example/ns/operators/sa/owner"
		workerID = "spiffe://cluster.example/ns/agents/sa/worker"
	)
	ms := newMockStore()
	ms.users["legacy-owner@example.com"] = &store.User{
		ID: "legacy-owner", Email: "legacy-owner@example.com", Role: "owner", IsActive: true,
	}
	ms.agents["migration-owner"] = &store.Agent{
		ID: "migration-owner-id", Name: "migration-owner", SPIFFEID: ownerID, Role: "owner", Status: "active",
	}
	ms.agents["worker"] = &store.Agent{
		ID: "worker-id", Name: "worker", Role: "no-access", Status: "active",
	}
	ms.agentVaultGrants = append(ms.agentVaultGrants, store.VaultGrant{
		ActorID: "worker-id", ActorType: "agent", VaultID: "root-ns-id", VaultName: "default", Role: "proxy",
	})
	ms.sessions["legacy-user-session"] = &store.Session{
		ID: "legacy-user-session", UserID: "legacy-owner", CreatedAt: time.Now(),
	}
	ms.sessions["legacy-worker-token"] = &store.Session{
		ID: "legacy-worker-token", AgentID: "worker-id", CreatedAt: time.Now(),
	}
	ms.sessions["legacy-scoped-token"] = &store.Session{
		ID: "legacy-scoped-token", VaultID: "root-ns-id", VaultRole: "admin", CreatedAt: time.Now(),
	}
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID:      "root-ns-id",
		ServicesJSON: `[{"name":"example","host":"api.example.com","auth":{"type":"passthrough"}}]`,
	}

	srv := newTestServer(withStore(ms))
	srv.authMode = "hybrid"
	ownerCert := spiffeTestCertificate(t, ownerID)
	workerCert := spiffeTestCertificate(t, workerID)

	legacyDiscover := migrationRequest(t, srv, http.MethodGet, "/discover", "", "legacy-worker-token", nil)
	if legacyDiscover.Code != http.StatusOK || !strings.Contains(legacyDiscover.Body.String(), "api.example.com") {
		t.Fatalf("legacy service access = %d %s", legacyDiscover.Code, legacyDiscover.Body.String())
	}

	bind := migrationRequest(t, srv, http.MethodPut, "/v1/agents/worker/spiffe-id",
		`{"spiffe_id":"`+workerID+`"}`, "", ownerCert)
	if bind.Code != http.StatusOK {
		t.Fatalf("bind SPIFFE ID = %d %s", bind.Code, bind.Body.String())
	}
	spiffeDiscover := migrationRequest(t, srv, http.MethodGet, "/discover", "", "", workerCert)
	if spiffeDiscover.Code != http.StatusOK || !strings.Contains(spiffeDiscover.Body.String(), "api.example.com") {
		t.Fatalf("hybrid SPIFFE service access = %d %s", spiffeDiscover.Code, spiffeDiscover.Body.String())
	}

	status := migrationRequest(t, srv, http.MethodGet, "/v1/admin/auth-migration", "", "", ownerCert)
	if status.Code != http.StatusOK {
		t.Fatalf("hybrid status = %d %s", status.Code, status.Body.String())
	}
	var before authMigrationStatus
	if err := json.Unmarshal(status.Body.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if before.ReadyToSwitch || before.PersistedSessions != 3 || len(before.UnboundActiveAgentNames) != 0 {
		t.Fatalf("hybrid inventory = %#v", before)
	}
	nonOwner := migrationRequest(t, srv, http.MethodGet, "/v1/admin/auth-migration", "", "", workerCert)
	if nonOwner.Code != http.StatusForbidden {
		t.Fatalf("non-owner migration status = %d", nonOwner.Code)
	}
	wrongConfirmation := migrationRequest(t, srv, http.MethodPost, "/v1/admin/auth-migration/revoke-legacy-sessions",
		`{"confirm":"not-approved"}`, "", ownerCert)
	if wrongConfirmation.Code != http.StatusBadRequest || len(ms.sessions) != 3 {
		t.Fatalf("wrong confirmation = %d sessions=%d", wrongConfirmation.Code, len(ms.sessions))
	}

	revoke := migrationRequest(t, srv, http.MethodPost, "/v1/admin/auth-migration/revoke-legacy-sessions",
		`{"confirm":"revoke-all-legacy-sessions"}`, "", ownerCert)
	if revoke.Code != http.StatusOK || len(ms.sessions) != 0 {
		t.Fatalf("legacy revocation = %d %s sessions=%d", revoke.Code, revoke.Body.String(), len(ms.sessions))
	}
	if len(ms.agentVaultGrants) != 1 || ms.agentVaultGrants[0].Role != "proxy" {
		t.Fatalf("migration changed grants: %#v", ms.agentVaultGrants)
	}

	srv.authMode = "spiffe"
	legacyRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/auth/register"},
		{http.MethodPost, "/v1/auth/verify"},
		{http.MethodPost, "/v1/auth/resend-verification"},
		{http.MethodPost, "/v1/auth/forgot-password"},
		{http.MethodPost, "/v1/auth/reset-password"},
		{http.MethodPost, "/v1/auth/login"},
		{http.MethodPost, "/v1/auth/change-password"},
		{http.MethodDelete, "/v1/auth/account"},
		{http.MethodGet, "/v1/auth/sessions"},
		{http.MethodDelete, "/v1/auth/sessions/example"},
		{http.MethodPost, "/v1/sessions"},
		{http.MethodGet, "/v1/sessions"},
		{http.MethodDelete, "/v1/sessions/example"},
		{http.MethodPost, "/v1/agents"},
		{http.MethodPost, "/v1/agents/worker/rotate"},
		{http.MethodPost, "/v1/users/invites"},
		{http.MethodGet, "/v1/users/invites"},
		{http.MethodDelete, "/v1/users/invites/example"},
		{http.MethodPost, "/v1/users/invites/example/reinvite"},
		{http.MethodGet, "/v1/users/invites/example/details"},
		{http.MethodPost, "/v1/users/invites/example/accept"},
		{http.MethodPost, "/v1/auth/logout"},
	}
	for _, route := range legacyRoutes {
		response := migrationRequest(t, srv, route.method, route.path, `{}`, "", nil)
		if response.Code != http.StatusNotFound {
			t.Errorf("legacy route %s %s = %d", route.method, route.path, response.Code)
		}
	}
	for _, token := range []string{"legacy-worker-token", "legacy-user-session", "legacy-scoped-token"} {
		response := migrationRequest(t, srv, http.MethodGet, "/discover", "", token, nil)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("revoked token %q status = %d", token, response.Code)
		}
	}
	finalDiscover := migrationRequest(t, srv, http.MethodGet, "/discover", "", "", workerCert)
	if finalDiscover.Code != http.StatusOK || !strings.Contains(finalDiscover.Body.String(), "api.example.com") {
		t.Fatalf("final SPIFFE service access = %d %s", finalDiscover.Code, finalDiscover.Body.String())
	}
	finalStatus := migrationRequest(t, srv, http.MethodGet, "/v1/admin/auth-migration", "", "", ownerCert)
	var after authMigrationStatus
	if err := json.Unmarshal(finalStatus.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if finalStatus.Code != http.StatusOK || !after.Complete || after.LegacyRoutesEnabled {
		t.Fatalf("final status = %d %#v", finalStatus.Code, after)
	}
}

func migrationRequest(t *testing.T, srv *Server, method, path, body, token string, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if path == "/discover" {
		req.Header.Set("X-Vault", "default")
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{cert},
			VerifiedChains:    [][]*x509.Certificate{{cert}},
		}
	}
	recorder := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(recorder, req)
	return recorder
}
