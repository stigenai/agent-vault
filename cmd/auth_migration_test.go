package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/session"
)

func TestAuthMigrationCommandsUseWorkloadIdentitySessionWithoutBearer(t *testing.T) {
	status := authMigrationStatusResponse{
		AuthMode:            "spiffe",
		ActiveAgents:        2,
		ActiveSPIFFEOwners:  1,
		ReadyToSwitch:       true,
		Complete:            true,
		LegacyRoutesEnabled: false,
		Blockers:            []string{},
	}
	var sawStatus, sawBind, sawRevoke bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("migration command sent bearer authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/admin/auth-migration":
			sawStatus = true
			_ = json.NewEncoder(w).Encode(status)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/worker/spiffe-id":
			sawBind = true
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "spiffe://cluster.example/ns/agents/sa/worker") {
				t.Errorf("bind body = %s", body)
			}
			_, _ = io.WriteString(w, `{"name":"worker"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/auth-migration/revoke-legacy-sessions":
			sawRevoke = true
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"confirm":"revoke-all-legacy-sessions"}` {
				t.Errorf("revoke body = %s", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked_sessions": 3, "status": status})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalLoader := loadWorkloadIdentitySession
	loadWorkloadIdentitySession = func() (*session.ClientSession, error) {
		return &session.ClientSession{Address: server.URL}, nil
	}
	t.Cleanup(func() { loadWorkloadIdentitySession = originalLoader })

	var output bytes.Buffer
	authMigrationStatusCmd.SetOut(&output)
	if err := authMigrationStatusCmd.Flags().Set("json", "false"); err != nil {
		t.Fatal(err)
	}
	if err := authMigrationStatusCmd.RunE(authMigrationStatusCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Auth mode: spiffe") {
		t.Fatalf("status output = %s", output.String())
	}

	output.Reset()
	authMigrationBindAgentCmd.SetOut(&output)
	if err := authMigrationBindAgentCmd.Flags().Set("spiffe-id", "spiffe://cluster.example/ns/agents/sa/worker"); err != nil {
		t.Fatal(err)
	}
	if err := authMigrationBindAgentCmd.RunE(authMigrationBindAgentCmd, []string{"worker"}); err != nil {
		t.Fatal(err)
	}

	output.Reset()
	authMigrationRevokeLegacyCmd.SetOut(&output)
	if err := authMigrationRevokeLegacyCmd.Flags().Set("confirm", "true"); err != nil {
		t.Fatal(err)
	}
	if err := authMigrationRevokeLegacyCmd.RunE(authMigrationRevokeLegacyCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Revoked 3 persisted legacy session") {
		t.Fatalf("revoke output = %s", output.String())
	}

	output.Reset()
	authMigrationVerifyCmd.SetOut(&output)
	if err := authMigrationVerifyCmd.RunE(authMigrationVerifyCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "SPIFFE-only migration verified") {
		t.Fatalf("verify output = %s", output.String())
	}
	if !sawStatus || !sawBind || !sawRevoke {
		t.Fatalf("requests: status=%t bind=%t revoke=%t", sawStatus, sawBind, sawRevoke)
	}
}

func TestAuthMigrationRevocationRequiresExplicitConfirmation(t *testing.T) {
	if err := authMigrationRevokeLegacyCmd.Flags().Set("confirm", "false"); err != nil {
		t.Fatal(err)
	}
	if err := authMigrationRevokeLegacyCmd.RunE(authMigrationRevokeLegacyCmd, nil); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("missing confirmation error = %v", err)
	}
}
