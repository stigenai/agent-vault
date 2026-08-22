package store

import (
	"context"
	"testing"
	"time"
)

func TestAuthMigrationInventoryAndGlobalLegacyRevocation(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.GetVault(ctx, DefaultVault)
	if err != nil {
		t.Fatal(err)
	}

	user, err := s.CreateUser(ctx, "legacy@example.com", []byte("hash"), []byte("salt"), "owner", 1, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUserSession(ctx, CreateUserSessionParams{
		UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	owner, err := s.CreateAgent(ctx, "spiffe-owner", user.ID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAgentSPIFFEID(ctx, owner.ID, "spiffe://cluster.example/ns/operators/sa/owner"); err != nil {
		t.Fatal(err)
	}
	unbound, err := s.CreateAgent(ctx, "legacy-worker", user.ID, "no-access")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAgentToken(ctx, unbound.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID: vault.ID, VaultRole: "admin", Label: "migration-checkpoint",
	}); err != nil {
		t.Fatal(err)
	}
	revoked, err := s.CreateAgent(ctx, "retired-unbound", user.ID, "no-access")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantVaultRole(ctx, unbound.ID, "agent", vault.ID, "proxy"); err != nil {
		t.Fatal(err)
	}

	inventory, err := s.InspectAuthMigration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Users != 1 || inventory.ActiveAgents != 2 || inventory.ActiveSPIFFEOwners != 1 {
		t.Fatalf("identity inventory = %#v", inventory)
	}
	if len(inventory.UnboundActiveAgentNames) != 1 || inventory.UnboundActiveAgentNames[0] != "legacy-worker" {
		t.Fatalf("unbound agents = %#v", inventory.UnboundActiveAgentNames)
	}
	if inventory.PersistedUserSessions != 1 || inventory.PersistedAgentSessions != 1 ||
		inventory.PersistedScopedSessions != 1 || inventory.PersistedSessions() != 3 {
		t.Fatalf("session inventory = %#v", inventory)
	}

	count, err := s.RevokeLegacySessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("revoked sessions = %d, want 3", count)
	}
	after, err := s.InspectAuthMigration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.PersistedSessions() != 0 || len(after.UnboundActiveAgentNames) != 1 {
		t.Fatalf("post-revocation inventory = %#v", after)
	}
	grants, err := s.ListActorGrants(ctx, unbound.ID)
	if err != nil || len(grants) != 1 || grants[0].Role != "proxy" {
		t.Fatalf("revocation changed grants: %#v, %v", grants, err)
	}
}
