package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Infisical/agent-vault/internal/store"
)

const revokeLegacySessionsConfirmation = "revoke-all-legacy-sessions"

type authMigrationStatus struct {
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

func (s *Server) authMigrationStatus(r *http.Request) (authMigrationStatus, error) {
	migrationStore, ok := s.store.(store.AuthMigrationStore)
	if !ok {
		return authMigrationStatus{}, errors.New("store does not support authentication migration")
	}
	inventory, err := migrationStore.InspectAuthMigration(r.Context())
	if err != nil {
		return authMigrationStatus{}, err
	}

	status := authMigrationStatus{
		AuthMode:                s.authMode,
		LegacyRoutesEnabled:     s.authMode != "spiffe",
		Users:                   inventory.Users,
		ActiveAgents:            inventory.ActiveAgents,
		UnboundActiveAgentNames: inventory.UnboundActiveAgentNames,
		PersistedUserSessions:   inventory.PersistedUserSessions,
		PersistedAgentSessions:  inventory.PersistedAgentSessions,
		PersistedScopedSessions: inventory.PersistedScopedSessions,
		PersistedSessions:       inventory.PersistedSessions(),
		ActiveSPIFFEOwners:      inventory.ActiveSPIFFEOwners,
	}
	if status.AuthMode != "hybrid" && status.AuthMode != "spiffe" {
		status.Blockers = append(status.Blockers, "server is not in hybrid or SPIFFE mode")
	}
	if status.ActiveSPIFFEOwners == 0 {
		status.Blockers = append(status.Blockers, "no active SPIFFE owner")
	}
	if len(status.UnboundActiveAgentNames) > 0 {
		status.Blockers = append(status.Blockers, "active agents without SPIFFE IDs")
	}
	if status.PersistedSessions > 0 {
		status.Blockers = append(status.Blockers, "persisted legacy sessions or tokens remain")
	}
	status.ReadyToSwitch = len(status.Blockers) == 0
	status.Complete = status.ReadyToSwitch && status.AuthMode == "spiffe" && !status.LegacyRoutesEnabled
	if status.UnboundActiveAgentNames == nil {
		status.UnboundActiveAgentNames = []string{}
	}
	if status.Blockers == nil {
		status.Blockers = []string{}
	}
	return status, nil
}

func (s *Server) handleAuthMigrationStatus(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	status, err := s.authMigrationStatus(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to inspect authentication migration")
		return
	}
	jsonOK(w, status)
}

func (s *Server) handleAuthMigrationRevokeLegacy(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	var body struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Confirm != revokeLegacySessionsConfirmation {
		jsonError(w, http.StatusBadRequest, `Confirmation must be "revoke-all-legacy-sessions"`)
		return
	}
	migrationStore, ok := s.store.(store.AuthMigrationStore)
	if !ok {
		jsonError(w, http.StatusInternalServerError, "Authentication migration is unavailable")
		return
	}
	revoked, err := migrationStore.RevokeLegacySessions(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke legacy sessions")
		return
	}
	s.logger.Info("revoked persisted legacy sessions for SPIFFE migration",
		slog.Int64("revoked_sessions", revoked),
		slog.String("actor_type", actor.Type),
		slog.String("actor_id", actor.ID))
	status, err := s.authMigrationStatus(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Legacy sessions revoked but migration status unavailable")
		return
	}
	jsonOK(w, map[string]any{
		"revoked_sessions": revoked,
		"status":           status,
	})
}
