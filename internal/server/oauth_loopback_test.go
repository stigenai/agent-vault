package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type oauthCapturingStore struct {
	*mockStore
	state *store.CredentialOAuthState
}

func (s *oauthCapturingStore) CreateCredentialOAuthState(_ context.Context, state *store.CredentialOAuthState) error {
	copy := *state
	s.state = &copy
	return nil
}

func TestOAuthConnectStoresAndReturnsExactLoopbackRedirect(t *testing.T) {
	base := newMockStore()
	base.agents["admin-bridge"] = &store.Agent{ID: "admin-bridge-id", Name: "admin-bridge", Role: "owner", Status: "active"}
	base.grants = map[string]map[string]string{"admin-bridge-id": {"root-ns-id": "admin"}}
	capture := &oauthCapturingStore{mockStore: base}
	srv := newTestServer(withStore(capture))
	srv.authMode = "spiffe"

	body := `{"vault":"default","key":"BLOCKS_OAUTH","authorization_url":"https://provider.example/authorize","token_url":"https://provider.example/token","client_id":"blocks-client"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/connect", strings.NewReader(body))
	req.Header.Set(oauth.LoopbackRedirectOriginHeader, "http://127.0.0.1:19443")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	req = req.WithContext(context.WithValue(req.Context(), sessionContextKey, &store.Session{AgentID: "admin-bridge-id"}))
	rec := httptest.NewRecorder()
	srv.handleOAuthConnect(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	const callback = "http://127.0.0.1:19443/v1/oauth/callback"
	if capture.state == nil || capture.state.RedirectURL != callback {
		t.Fatalf("stored OAuth state = %#v, want redirect %q", capture.state, callback)
	}
	response := struct {
		AuthorizationURL string `json:"authorization_url"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(response.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := authURL.Query().Get("redirect_uri"); got != callback {
		t.Fatalf("authorization redirect_uri = %q, want %q", got, callback)
	}
}

func TestOAuthConnectRedirectURIRequiresSPIFFEOwner(t *testing.T) {
	ownerAgent := &Actor{ID: "admin-bridge", Type: "agent", Role: "owner", Agent: &store.Agent{ID: "admin-bridge", Role: "owner"}}
	memberAgent := &Actor{ID: "member", Type: "agent", Role: "member", Agent: &store.Agent{ID: "member", Role: "member"}}
	ownerUser := &Actor{ID: "owner-user", Type: "user", Role: "owner", User: &store.User{ID: "owner-user", Role: "owner"}}

	tests := []struct {
		name       string
		authMode   string
		actor      *Actor
		withTLS    bool
		origin     string
		wantOK     bool
		wantStatus int
	}{
		{name: "SPIFFE owner agent", authMode: "spiffe", actor: ownerAgent, withTLS: true, origin: "http://127.0.0.1:19443", wantOK: true},
		{name: "legacy mode", authMode: "legacy", actor: ownerAgent, withTLS: true, origin: "http://127.0.0.1:19443", wantStatus: http.StatusForbidden},
		{name: "missing peer certificate", authMode: "spiffe", actor: ownerAgent, origin: "http://127.0.0.1:19443", wantStatus: http.StatusForbidden},
		{name: "member agent", authMode: "spiffe", actor: memberAgent, withTLS: true, origin: "http://127.0.0.1:19443", wantStatus: http.StatusForbidden},
		{name: "owner user", authMode: "spiffe", actor: ownerUser, withTLS: true, origin: "http://127.0.0.1:19443", wantStatus: http.StatusForbidden},
		{name: "unmapped actor", authMode: "spiffe", withTLS: true, origin: "http://127.0.0.1:19443", wantStatus: http.StatusForbidden},
		{name: "non-loopback origin", authMode: "spiffe", actor: ownerAgent, withTLS: true, origin: "http://attacker.example:19443", wantStatus: http.StatusBadRequest},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer()
			srv.authMode = tc.authMode
			req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/connect", nil)
			req.Header.Set(oauth.LoopbackRedirectOriginHeader, tc.origin)
			if tc.withTLS {
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
			}
			rec := httptest.NewRecorder()
			got, ok := srv.oauthConnectRedirectURI(rec, req, tc.actor)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v; status=%d body=%s", ok, tc.wantOK, rec.Code, rec.Body.String())
			}
			if tc.wantOK && got != "http://127.0.0.1:19443/v1/oauth/callback" {
				t.Fatalf("redirect URI = %q", got)
			}
			if !tc.wantOK && rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "attacker.example") {
				t.Fatalf("unsafe origin echoed in response: %s", rec.Body.String())
			}
		})
	}
}

func TestOAuthConnectRedirectURIDefaultAndDuplicateHeader(t *testing.T) {
	srv := newTestServer(withBaseURL("https://agent-vault.example"))
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/connect", nil)
	rec := httptest.NewRecorder()
	got, ok := srv.oauthConnectRedirectURI(rec, req, nil)
	if !ok || got != "https://agent-vault.example/v1/oauth/callback" {
		t.Fatalf("default redirect = %q, ok=%v", got, ok)
	}

	req.Header.Add(oauth.LoopbackRedirectOriginHeader, "http://127.0.0.1:19443")
	req.Header.Add(oauth.LoopbackRedirectOriginHeader, "http://localhost:19443")
	rec = httptest.NewRecorder()
	if _, ok := srv.oauthConnectRedirectURI(rec, req, nil); ok || rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate header accepted: ok=%v status=%d", ok, rec.Code)
	}
}

func TestOAuthStateRedirectURIFailsClosedOnStoredValue(t *testing.T) {
	srv := newTestServer(withBaseURL("https://agent-vault.example"))
	for _, tc := range []struct {
		name  string
		state *store.CredentialOAuthState
		want  string
	}{
		{name: "loopback", state: &store.CredentialOAuthState{RedirectURL: "http://127.0.0.1:19443/v1/oauth/callback"}, want: "http://127.0.0.1:19443/v1/oauth/callback"},
		{name: "empty legacy state", state: &store.CredentialOAuthState{}, want: "https://agent-vault.example/v1/oauth/callback"},
		{name: "external database value", state: &store.CredentialOAuthState{RedirectURL: "https://attacker.example/callback"}, want: "https://agent-vault.example/v1/oauth/callback"},
		{name: "loopback wrong path", state: &store.CredentialOAuthState{RedirectURL: "http://127.0.0.1:19443/export"}, want: "https://agent-vault.example/v1/oauth/callback"},
		{name: "nil state", want: "https://agent-vault.example/v1/oauth/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := srv.oauthStateRedirectURI(tc.state); got != tc.want {
				t.Fatalf("redirect = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOAuthCompletionRedirectUsesOnlyValidatedLoopbackOrigin(t *testing.T) {
	srv := newTestServer(withBaseURL("https://agent-vault.example"))
	for _, tc := range []struct {
		name   string
		origin string
		want   string
	}{
		{name: "bridge", origin: "http://127.0.0.1:19443", want: "http://127.0.0.1:19443/oauth/complete?status=success&vault=blocks&key=BLOCKS_TOKEN"},
		{name: "external rejected", origin: "https://attacker.example", want: "https://agent-vault.example/oauth/complete?status=success&vault=blocks&key=BLOCKS_TOKEN"},
		{name: "absent", want: "https://agent-vault.example/oauth/complete?status=success&vault=blocks&key=BLOCKS_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/oauth/callback", nil)
			if tc.origin != "" {
				req.Header.Set(oauth.LoopbackRedirectOriginHeader, tc.origin)
			}
			rec := httptest.NewRecorder()
			srv.redirectOAuthComplete(rec, req, "blocks", "BLOCKS_TOKEN", "success", "")
			if location := rec.Header().Get("Location"); rec.Code != http.StatusFound || location != tc.want {
				t.Fatalf("status=%d location=%q, want %q", rec.Code, location, tc.want)
			}
		})
	}
}
