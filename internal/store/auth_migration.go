package store

import (
	"context"
	"fmt"
)

// InspectAuthMigration returns only identities and counts. It never reads or
// returns session hashes, password material, credentials, or provider values.
func (s *SQLStore) InspectAuthMigration(ctx context.Context) (AuthMigrationInventory, error) {
	var result AuthMigrationInventory
	counts := []struct {
		label string
		query string
		dest  *int
	}{
		{"users", "SELECT COUNT(*) FROM users", &result.Users},
		{"active agents", "SELECT COUNT(*) FROM agents WHERE status = 'active'", &result.ActiveAgents},
		{"user sessions", "SELECT COUNT(*) FROM sessions WHERE user_id IS NOT NULL", &result.PersistedUserSessions},
		{"agent sessions", "SELECT COUNT(*) FROM sessions WHERE agent_id IS NOT NULL", &result.PersistedAgentSessions},
		{"scoped sessions", "SELECT COUNT(*) FROM sessions WHERE user_id IS NULL AND agent_id IS NULL", &result.PersistedScopedSessions},
		{"SPIFFE owners", "SELECT COUNT(*) FROM agents WHERE status = 'active' AND role = 'owner' AND spiffe_id IS NOT NULL AND spiffe_id <> ''", &result.ActiveSPIFFEOwners},
	}
	for _, count := range counts {
		if err := s.db.QueryRowContext(ctx, count.query).Scan(count.dest); err != nil {
			return AuthMigrationInventory{}, fmt.Errorf("counting auth migration %s: %w", count.label, err)
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT name
		FROM agents
		WHERE status = 'active' AND (spiffe_id IS NULL OR spiffe_id = '')
		ORDER BY name`)
	if err != nil {
		return AuthMigrationInventory{}, fmt.Errorf("listing unbound auth migration agents: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return AuthMigrationInventory{}, fmt.Errorf("scanning unbound auth migration agent: %w", err)
		}
		result.UnboundActiveAgentNames = append(result.UnboundActiveAgentNames, name)
	}
	if err := rows.Err(); err != nil {
		return AuthMigrationInventory{}, fmt.Errorf("listing unbound auth migration agents: %w", err)
	}
	return result, nil
}

// RevokeLegacySessions invalidates every persisted session in one transaction.
// Workload SVIDs are unaffected because SPIFFE authentication is stateless.
func (s *SQLStore) RevokeLegacySessions(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("beginning legacy session revocation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, "DELETE FROM sessions")
	if err != nil {
		return 0, fmt.Errorf("revoking legacy sessions: %w", err)
	}
	revoked, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("counting revoked legacy sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing legacy session revocation: %w", err)
	}
	return revoked, nil
}
