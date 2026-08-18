package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestMetricsEndpointIsAuthenticatedAndSecretFree(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	now := time.Now().UTC()
	ms.credentialSources["root-ns-id:TOP_SECRET_KEY"] = &store.CredentialSource{
		VaultID: "root-ns-id", CredentialKey: "TOP_SECRET_KEY",
		ProviderName: "provider-secret-name", Reference: "secret/provider/reference",
		LastErrorCode: "secret-error-detail", Health: store.CredentialSourceHealthStale,
		LastSuccessAt: &now, MaxStalenessSeconds: 60, RefreshFailures: 3,
	}
	srv := NewWithRuntime("127.0.0.1:0", ms, make([]byte, 32), nil, true,
		"http://127.0.0.1", slog.New(slog.DiscardHandler), RuntimeOptions{
			MetricsEnabled: true,
			RateLimit:      ratelimit.DefaultsFor(ratelimit.ProfileDefault),
		})

	unauthorized := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	unauthorizedRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(unauthorizedRec, unauthorized)
	if unauthorizedRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d, want 401", unauthorizedRec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"agent_vault_database_up", `agent_vault_secret_sources{health="stale"} 1`,
		"agent_vault_secret_source_consecutive_refresh_failures 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"TOP_SECRET_KEY", "provider-secret-name", "secret/provider/reference", "secret-error-detail", token} {
		if strings.Contains(body, forbidden) {
			t.Errorf("metrics leaked %q:\n%s", forbidden, body)
		}
	}
}

func TestMetricsEndpointIsAbsentUnlessEnabled(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled metrics status = %d, want 404", rec.Code)
	}
}
