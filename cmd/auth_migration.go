package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

type authMigrationStatusResponse struct {
	AuthMode                string   `json:"auth_mode"`
	LegacyRoutesEnabled     bool     `json:"legacy_routes_enabled"`
	Users                   int      `json:"users"`
	ActiveAgents            int      `json:"active_agents"`
	UnboundActiveAgentNames []string `json:"unbound_active_agent_names"`
	PersistedUserSessions   int      `json:"persisted_user_sessions"`
	PersistedAgentSessions  int      `json:"persisted_agent_sessions"`
	PersistedScopedSessions int      `json:"persisted_scoped_sessions"`
	PersistedSessions       int      `json:"persisted_sessions"`
	ActiveSPIFFEOwners      int      `json:"active_spiffe_owners"`
	ReadyToSwitch           bool     `json:"ready_to_switch"`
	Complete                bool     `json:"complete"`
	Blockers                []string `json:"blockers"`
}

var authMigrationCmd = &cobra.Command{
	Use:   "migration",
	Short: "Stage and verify migration to SPIFFE-only authentication",
}

var authMigrationStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Inventory SPIFFE bindings and persisted legacy sessions",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		status, raw, err := fetchAuthMigrationStatus()
		if err != nil {
			return err
		}
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			var pretty any
			if err := json.Unmarshal(raw, &pretty); err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(pretty, "", "  ")
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
			return err
		}
		writeAuthMigrationStatus(cmd, status)
		return nil
	},
}

var authMigrationBindAgentCmd = &cobra.Command{
	Use:   "bind-agent <name>",
	Short: "Bind an existing agent to one exact SPIFFE ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		spiffeID, _ := cmd.Flags().GetString("spiffe-id")
		if strings.TrimSpace(spiffeID) == "" {
			return fmt.Errorf("--spiffe-id is required")
		}
		body, err := json.Marshal(map[string]string{"spiffe_id": spiffeID})
		if err != nil {
			return err
		}
		if _, err := authMigrationRequest(http.MethodPut, "/v1/agents/"+url.PathEscape(args[0])+"/spiffe-id", body); err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q bound to %s.\n", successText("✓"), args[0], spiffeID)
		return err
	},
}

var authMigrationRevokeLegacyCmd = &cobra.Command{
	Use:   "revoke-legacy-sessions",
	Short: "Revoke every password session, scoped token, and durable agent token",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			return fmt.Errorf("refusing global revocation without --confirm")
		}
		body := []byte(`{"confirm":"revoke-all-legacy-sessions"}`)
		raw, err := authMigrationRequest(http.MethodPost, "/v1/admin/auth-migration/revoke-legacy-sessions", body)
		if err != nil {
			return err
		}
		var result struct {
			RevokedSessions int                         `json:"revoked_sessions"`
			Status          authMigrationStatusResponse `json:"status"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return fmt.Errorf("parsing migration revocation response: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Revoked %d persisted legacy session(s).\n", successText("✓"), result.RevokedSessions)
		writeAuthMigrationStatus(cmd, &result.Status)
		return nil
	},
}

var authMigrationVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Require the running server to be fully SPIFFE-only",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		status, _, err := fetchAuthMigrationStatus()
		if err != nil {
			return err
		}
		writeAuthMigrationStatus(cmd, status)
		if !status.Complete {
			return fmt.Errorf("SPIFFE-only migration is not complete")
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), successText("✓ SPIFFE-only migration verified."))
		return err
	},
}

func authMigrationRequest(method, path string, body []byte) ([]byte, error) {
	sess, _, err := resolveSession()
	if err != nil {
		return nil, err
	}
	return doAdminRequestWithBody(method, strings.TrimRight(sess.Address, "/")+path, sess.Token, body)
}

func fetchAuthMigrationStatus() (*authMigrationStatusResponse, []byte, error) {
	raw, err := authMigrationRequest(http.MethodGet, "/v1/admin/auth-migration", nil)
	if err != nil {
		return nil, nil, err
	}
	var status authMigrationStatusResponse
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, nil, fmt.Errorf("parsing authentication migration status: %w", err)
	}
	return &status, raw, nil
}

func writeAuthMigrationStatus(cmd *cobra.Command, status *authMigrationStatusResponse) {
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "Auth mode: %s\n", status.AuthMode)
	_, _ = fmt.Fprintf(w, "SPIFFE owners: %d\n", status.ActiveSPIFFEOwners)
	_, _ = fmt.Fprintf(w, "Active agents: %d (unbound: %d)\n", status.ActiveAgents, len(status.UnboundActiveAgentNames))
	if len(status.UnboundActiveAgentNames) > 0 {
		_, _ = fmt.Fprintf(w, "Unbound agents: %s\n", strings.Join(status.UnboundActiveAgentNames, ", "))
	}
	_, _ = fmt.Fprintf(w, "Persisted legacy sessions: %d (user=%d agent=%d scoped=%d)\n",
		status.PersistedSessions, status.PersistedUserSessions, status.PersistedAgentSessions, status.PersistedScopedSessions)
	_, _ = fmt.Fprintf(w, "Legacy routes enabled: %t\n", status.LegacyRoutesEnabled)
	_, _ = fmt.Fprintf(w, "Ready to switch: %t\n", status.ReadyToSwitch)
	if len(status.Blockers) > 0 {
		_, _ = fmt.Fprintf(w, "Blockers: %s\n", strings.Join(status.Blockers, "; "))
	}
}

func init() {
	authMigrationStatusCmd.Flags().Bool("json", false, "emit machine-readable JSON")
	authMigrationBindAgentCmd.Flags().String("spiffe-id", "", "exact SPIFFE ID assigned by SPIRE")
	authMigrationRevokeLegacyCmd.Flags().Bool("confirm", false, "confirm revocation of every persisted legacy session and token")
	authMigrationCmd.AddCommand(authMigrationStatusCmd)
	authMigrationCmd.AddCommand(authMigrationBindAgentCmd)
	authMigrationCmd.AddCommand(authMigrationRevokeLegacyCmd)
	authMigrationCmd.AddCommand(authMigrationVerifyCmd)
	authCmd.AddCommand(authMigrationCmd)
}
