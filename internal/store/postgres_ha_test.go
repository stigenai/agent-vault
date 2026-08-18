package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const postgresHATestURLEnv = "AGENT_VAULT_TEST_POSTGRES_URL"

type postgresHATestDatabase struct {
	dsn             string
	applicationName string
	admin           *sql.DB
	schema          string
}

func newPostgresHATestDatabase(t *testing.T) *postgresHATestDatabase {
	t.Helper()
	rawURL := os.Getenv(postgresHATestURLEnv)
	if rawURL == "" {
		t.Skipf("set %s to run PostgreSQL HA integration tests", postgresHATestURLEnv)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", postgresHATestURLEnv, err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		t.Fatalf("%s must use postgres:// or postgresql://", postgresHATestURLEnv)
	}

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "agent_vault_ha_" + hex.EncodeToString(suffix[:])
	applicationName := "agent-vault-ha-" + hex.EncodeToString(suffix[:])

	adminURL := *parsed
	adminQuery := adminURL.Query()
	adminQuery.Del("search_path")
	adminQuery.Set("application_name", applicationName+"-admin")
	adminURL.RawQuery = adminQuery.Encode()
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Fatalf("open PostgreSQL admin connection: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create PostgreSQL test schema: %v", err)
	}

	testURL := *parsed
	testQuery := testURL.Query()
	testQuery.Set("search_path", schema)
	testQuery.Set("application_name", applicationName)
	testURL.RawQuery = testQuery.Encode()
	database := &postgresHATestDatabase{
		dsn:             testURL.String(),
		applicationName: applicationName,
		admin:           admin,
		schema:          schema,
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		_ = admin.Close()
	})
	return database
}

func (database *postgresHATestDatabase) openReplicas(t *testing.T, count int) []*SQLStore {
	t.Helper()
	stores := make([]*SQLStore, count)
	errs := make([]error, count)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(count)
	for index := range count {
		go func() {
			defer workers.Done()
			<-start
			stores[index], errs[index] = openPostgres(StoreConfig{
				DatabaseURL:     database.dsn,
				MaxOpenConns:    4,
				MaxIdleConns:    2,
				ConnMaxLifetime: 5 * time.Minute,
				ConnectTimeout:  10 * time.Second,
				PoolConfigured:  true,
			})
		}()
	}
	close(start)
	workers.Wait()
	for index, err := range errs {
		if err != nil {
			for _, store := range stores {
				if store != nil {
					_ = store.Close()
				}
			}
			t.Fatalf("open PostgreSQL replica %d: %v", index, err)
		}
	}
	return stores
}

func closePostgresHAStores(stores []*SQLStore) {
	for _, store := range stores {
		if store != nil {
			_ = store.Close()
		}
	}
}

func TestPostgresHAAdvisoryLockSerializesConnections(t *testing.T) {
	database := newPostgresHATestDatabase(t)
	const contenders = 8
	connections := make([]*sql.DB, contenders)
	for index := range contenders {
		var err error
		connections[index], err = sql.Open("pgx", database.dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer connections[index].Close()
	}
	start := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	var workers sync.WaitGroup
	workers.Add(contenders)
	errs := make(chan error, contenders)
	for _, db := range connections {
		go func() {
			defer workers.Done()
			<-start
			conn, err := db.Conn(context.Background())
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			var lockResult any
			if err := conn.QueryRowContext(context.Background(), "SELECT pg_advisory_lock($1)", int64(7956324891)).Scan(&lockResult); err != nil {
				errs <- err
				return
			}
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			active.Add(-1)
			var unlocked bool
			if err := conn.QueryRowContext(context.Background(), "SELECT pg_advisory_unlock($1)", int64(7956324891)).Scan(&unlocked); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent advisory lock holders = %d, want 1", maximum.Load())
	}
}

func TestPostgresHAConcurrentMigrationsAndSPIFFEBootstrap(t *testing.T) {
	database := newPostgresHATestDatabase(t)
	stores := database.openReplicas(t, 8)
	defer closePostgresHAStores(stores)

	var migrationCount, distinctMigrationCount int
	if err := stores[0].db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT name) FROM schema_migrations`).Scan(&migrationCount, &distinctMigrationCount); err != nil {
		t.Fatalf("inspect migration ledger: %v", err)
	}
	gormMigMu.Lock()
	expectedMigrations := len(gormMigrations)
	gormMigMu.Unlock()
	if migrationCount != expectedMigrations || distinctMigrationCount != expectedMigrations {
		t.Fatalf("migration ledger = total %d distinct %d, want %d", migrationCount, distinctMigrationCount, expectedMigrations)
	}
	for _, table := range []string{"agents", "credential_sources", "dek_wrappings", "managed_resources", "vault_grants"} {
		var relation sql.NullString
		if err := stores[0].db.QueryRow(`SELECT to_regclass($1)`, table).Scan(&relation); err != nil || !relation.Valid {
			t.Fatalf("migrated table %s = %#v, %v", table, relation, err)
		}
	}

	configuredIDs := []string{
		"spiffe://cluster.example/ns/agent-vault/sa/owner-a",
		"spiffe://cluster.example/ns/agent-vault/sa/owner-b",
	}
	results := make([]SPIFFEOwnerBootstrap, len(stores))
	errs := make([]error, len(stores))
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(len(stores))
	for index, store := range stores {
		go func() {
			defer workers.Done()
			<-start
			results[index], errs[index] = store.BootstrapSPIFFEOwners(context.Background(), configuredIDs)
		}()
	}
	close(start)
	workers.Wait()
	applied := 0
	for index, result := range results {
		if errs[index] != nil {
			t.Fatalf("bootstrap replica %d: %v", index, errs[index])
		}
		if result.Applied {
			applied++
		}
		if result.OwnerCount != len(configuredIDs) || result.SPIFFEOwners != len(configuredIDs) {
			t.Fatalf("bootstrap replica %d result = %#v", index, result)
		}
		gotIDs := append([]string(nil), result.ConfiguredIDs...)
		sort.Strings(gotIDs)
		if strings.Join(gotIDs, "\n") != strings.Join(configuredIDs, "\n") {
			t.Fatalf("bootstrap replica %d IDs = %v", index, gotIDs)
		}
	}
	if applied != 1 {
		t.Fatalf("bootstrap applied by %d replicas, want exactly 1", applied)
	}

	beforeRollingRestart := migrationCount
	for index := 1; index < 4; index++ {
		_ = stores[index].Close()
		stores[index] = nil
	}
	replacements := database.openReplicas(t, 3)
	stores = append(stores, replacements...)
	if err := stores[0].Ping(context.Background()); err != nil {
		t.Fatalf("old replica failed after rolling replacements: %v", err)
	}
	if err := replacements[0].db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != beforeRollingRestart {
		t.Fatalf("rolling replacement changed migration ledger from %d to %d", beforeRollingRestart, migrationCount)
	}
	replayed, err := replacements[0].BootstrapSPIFFEOwners(context.Background(), configuredIDs)
	if err != nil || replayed.Applied {
		t.Fatalf("rolling replacement replayed owner bootstrap: %#v, %v", replayed, err)
	}
}

func TestPostgresHAAuthMigrationInventoryAndRevocation(t *testing.T) {
	database := newPostgresHATestDatabase(t)
	stores := database.openReplicas(t, 1)
	defer closePostgresHAStores(stores)
	s := stores[0]
	ctx := context.Background()

	vault, err := s.GetVault(ctx, DefaultVault)
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.CreateUser(ctx, "postgres-migration@example.com", []byte("hash"), []byte("salt"), "owner", 1, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.CreateAgent(ctx, "postgres-spiffe-owner", user.ID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAgentSPIFFEID(ctx, owner.ID, "spiffe://cluster.example/ns/operators/sa/postgres-owner"); err != nil {
		t.Fatal(err)
	}
	worker, err := s.CreateAgent(ctx, "postgres-legacy-worker", user.ID, "no-access")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GrantVaultRole(ctx, worker.ID, "agent", vault.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUserSession(ctx, CreateUserSessionParams{UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAgentToken(ctx, worker.ID, nil); err != nil {
		t.Fatal(err)
	}

	inventory, err := s.InspectAuthMigration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.ActiveSPIFFEOwners != 1 || inventory.PersistedSessions() != 2 ||
		len(inventory.UnboundActiveAgentNames) != 1 || inventory.UnboundActiveAgentNames[0] != worker.Name {
		t.Fatalf("PostgreSQL migration inventory = %#v", inventory)
	}
	if revoked, err := s.RevokeLegacySessions(ctx); err != nil || revoked != 2 {
		t.Fatalf("PostgreSQL revoked sessions = %d, %v", revoked, err)
	}
	if err := s.UpdateAgentSPIFFEID(ctx, worker.ID, "spiffe://cluster.example/ns/agents/sa/postgres-worker"); err != nil {
		t.Fatal(err)
	}
	after, err := s.InspectAuthMigration(ctx)
	if err != nil || after.PersistedSessions() != 0 || len(after.UnboundActiveAgentNames) != 0 {
		t.Fatalf("PostgreSQL final migration inventory = %#v, %v", after, err)
	}
	grants, err := s.ListActorGrants(ctx, worker.ID)
	if err != nil || len(grants) != 1 || grants[0].Role != "proxy" {
		t.Fatalf("PostgreSQL migration changed grants = %#v, %v", grants, err)
	}
}

func TestPostgresHARefreshClaimsSurviveConnectionLoss(t *testing.T) {
	database := newPostgresHATestDatabase(t)
	stores := database.openReplicas(t, 6)
	defer closePostgresHAStores(stores)
	ctx := context.Background()
	vault, err := stores[0].CreateVault(ctx, "postgres-ha-refresh")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const sourceCount = 24
	for index := range sourceCount {
		key := fmt.Sprintf("HA_TOKEN_%02d", index)
		if _, err := stores[0].SetCredential(ctx, vault.ID, key, []byte("ciphertext"), []byte("nonce")); err != nil {
			t.Fatal(err)
		}
		if _, err := stores[0].SetCredentialSource(ctx, CredentialSource{
			VaultID:                vault.ID,
			CredentialKey:          key,
			Mode:                   CredentialSourceModeReference,
			Kind:                   CredentialSourceAWSSecretsManager,
			ProviderName:           "aws-production",
			Reference:              "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + key,
			RefreshIntervalSeconds: 60,
			MaxStalenessSeconds:    300,
			Health:                 CredentialSourceHealthPending,
			NextRefreshAt:          timePtr(now.Add(-time.Second)),
		}); err != nil {
			t.Fatal(err)
		}
	}

	type claimResult struct {
		worker  string
		sources []CredentialSource
		err     error
	}
	results := make([]claimResult, len(stores))
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(len(stores))
	lease := 5 * time.Second
	for index, store := range stores {
		go func() {
			defer workers.Done()
			<-start
			worker := fmt.Sprintf("replica-%d", index)
			sources, err := store.ClaimCredentialSources(ctx, worker, now, lease, sourceCount)
			results[index] = claimResult{worker: worker, sources: sources, err: err}
		}()
	}
	close(start)
	workers.Wait()
	claimed := make(map[string]string, sourceCount)
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("claim by %s: %v", result.worker, result.err)
		}
		for _, source := range result.sources {
			identity := source.VaultID + "/" + source.CredentialKey
			if previous, duplicate := claimed[identity]; duplicate {
				t.Fatalf("source %s claimed by both %s and %s", identity, previous, result.worker)
			}
			claimed[identity] = result.worker
		}
	}
	if len(claimed) != sourceCount {
		t.Fatalf("coordinated claims = %d, want %d", len(claimed), sourceCount)
	}

	rows, err := database.admin.QueryContext(ctx, `SELECT pg_terminate_backend(pid)
		FROM pg_stat_activity WHERE application_name = $1 AND pid <> pg_backend_pid()`, database.applicationName)
	if err != nil {
		t.Fatalf("terminate replica connections: %v", err)
	}
	terminated := 0
	for rows.Next() {
		var didTerminate bool
		if err := rows.Scan(&didTerminate); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if didTerminate {
			terminated++
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if terminated == 0 {
		t.Fatal("test did not terminate any PostgreSQL replica connections")
	}
	for index, store := range stores {
		deadline := time.Now().Add(10 * time.Second)
		for {
			pingCtx, cancel := context.WithTimeout(ctx, time.Second)
			err := store.Ping(pingCtx)
			cancel()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("replica %d did not reconnect: %v", index, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	takeoverAt := now.Add(lease + time.Second)
	takeover, err := stores[1].ClaimCredentialSources(ctx, "rolling-replacement", takeoverAt, time.Minute, sourceCount)
	if err != nil {
		t.Fatalf("claim after connection loss: %v", err)
	}
	if len(takeover) != sourceCount {
		t.Fatalf("expired claim takeover = %d, want %d", len(takeover), sourceCount)
	}
	for _, source := range takeover {
		if source.ClaimOwner != "rolling-replacement" {
			t.Fatalf("takeover owner for %s = %q", source.CredentialKey, source.ClaimOwner)
		}
	}
}
