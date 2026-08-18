package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/ca"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/keywrap/agerecovery"
	"github.com/Infisical/agent-vault/internal/store"
)

type backupDrillReport struct {
	BackupDurationMS      int64  `json:"backup_duration_ms"`
	ObservedSnapshotLagMS int64  `json:"observed_rpo_snapshot_lag_ms"`
	RestoreRecoveryMS     int64  `json:"observed_rto_restore_recovery_ms"`
	Vaults                int    `json:"vaults"`
	CredentialSources     int    `json:"credential_sources"`
	Grants                int    `json:"grants"`
	RequestAuditRows      int    `json:"request_audit_rows"`
	DEKWrappings          int    `json:"dek_wrappings"`
	RecoveryAuditRows     int    `json:"recovery_audit_rows"`
	PrimaryProvider       string `json:"primary_provider"`
	CAUsable              bool   `json:"ca_usable"`
}

func TestPostgresBackupRestoreAndExplicitRecovery(t *testing.T) {
	sourceURL := os.Getenv("AGENT_VAULT_TEST_BACKUP_SOURCE_URL")
	targetURL := os.Getenv("AGENT_VAULT_TEST_BACKUP_TARGET_URL")
	if sourceURL == "" || targetURL == "" {
		t.Skip("set AGENT_VAULT_TEST_BACKUP_SOURCE_URL and AGENT_VAULT_TEST_BACKUP_TARGET_URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	source := openBackupDrillStore(t, sourceURL)

	original, verification, err := auth.SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Wipe()
	if err := source.SetMasterKeyRecord(ctx, verificationToStoreRecord(verification)); err != nil {
		t.Fatal(err)
	}
	persistence := source.(store.KeyWrappingStore)
	binding, err := keywrap.EnsureInstanceBinding(ctx, persistence)
	if err != nil {
		t.Fatal(err)
	}
	primaryWrapper := &commandTestWrapper{identity: keywrap.Identity{Provider: "test-kms", KeyID: "backup-primary"}}
	if _, err := keywrap.EnsurePrimary(ctx, persistence, primaryWrapper, original.Key(), binding); err != nil {
		t.Fatal(err)
	}
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recoveryWrapper, err := agerecovery.New(ageIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keywrap.EnsureAdditional(ctx, persistence, recoveryWrapper, original.Key(), binding); err != nil {
		t.Fatal(err)
	}

	ownerID := "spiffe://cluster.example/ns/recovery/sa/operator"
	if _, err := source.BootstrapSPIFFEOwners(ctx, []string{ownerID}); err != nil {
		t.Fatal(err)
	}
	owner, err := source.GetAgentBySPIFFEID(ctx, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := source.CreateVault(ctx, "backup-drill")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.GrantVaultRole(ctx, owner.ID, "agent", vault.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.SetBrokerConfig(ctx, vault.ID, `[{"name":"example","host":"api.example.com","auth":{"type":"bearer","token":"API_TOKEN"}}]`); err != nil {
		t.Fatal(err)
	}
	secretCiphertext, secretNonce, err := vaultcrypto.Encrypt([]byte("restored-secret"), original.Key())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.SetCredential(ctx, vault.ID, "API_TOKEN", secretCiphertext, secretNonce); err != nil {
		t.Fatal(err)
	}
	lastWrite := time.Now().UTC()
	if _, err := source.SetCredentialSource(ctx, store.CredentialSource{
		VaultID: vault.ID, CredentialKey: "API_TOKEN", Mode: store.CredentialSourceModeReference,
		Kind: store.CredentialSourceAWSSecretsManager, ProviderName: "aws-production",
		Reference: "agent-vault/backup-drill#token", RefreshIntervalSeconds: 300,
		MaxStalenessSeconds: 3600, Health: store.CredentialSourceHealthOK,
		CacheUpdatedAt: &lastWrite, LastRefreshAt: &lastWrite, LastSuccessAt: &lastWrite,
		NextRefreshAt: timePointer(lastWrite.Add(5 * time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.InsertRequestLogs(ctx, []store.RequestLog{{
		VaultID: vault.ID, ActorType: "agent", ActorID: owner.ID, Ingress: "mitm",
		Method: "GET", Host: "api.example.com", Path: "/v1/check", MatchedService: "example",
		CredentialKeys: []string{"API_TOKEN"}, Status: 200, LatencyMs: 12, CreatedAt: lastWrite,
	}}); err != nil {
		t.Fatal(err)
	}
	sourceCA, err := ca.New(original.Key(), ca.Options{Store: &caStoreAdapter{db: source}})
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := sourceCA.RootPEM()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	dumpPath := filepath.Join(t.TempDir(), "agent-vault.dump")
	if err := os.WriteFile(dumpPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	backupStarted := time.Now()
	runPostgresTool(t, ctx, sourceURL, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--dbname", postgresDatabaseName(t, sourceURL), "--file", dumpPath)
	backupCompleted := time.Now()
	if info, err := os.Stat(dumpPath); err != nil || info.Size() == 0 || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("backup artifact is missing, empty, or too permissive: info=%v err=%v", info, err)
	}

	restoreStarted := time.Now()
	runPostgresTool(t, ctx, targetURL, "pg_restore", "--no-owner", "--no-privileges", "--exit-on-error", "--dbname", postgresDatabaseName(t, targetURL), dumpPath)
	restored := openBackupDrillStore(t, targetURL)
	defer restored.Close()
	restoredPersistence := restored.(store.KeyWrappingStore)
	restoredBinding, err := keywrap.EnsureInstanceBinding(ctx, restoredPersistence)
	if err != nil {
		t.Fatal(err)
	}
	restoredPrimary, err := restoredPersistence.GetPrimaryDEKWrapping(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restoredDEK, err := keywrap.UnwrapRecord(ctx, restoredPrimary, primaryWrapper, restoredBinding)
	if err != nil {
		t.Fatalf("primary provider could not unwrap restored DEK: %v", err)
	}
	defer vaultcrypto.WipeBytes(restoredDEK)
	masterRecord, err := restored.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unlocked, err := auth.UnlockWithDEK(restoredDEK, buildVerificationRecord(masterRecord))
	if err != nil {
		t.Fatalf("restored DEK failed sentinel verification: %v", err)
	}
	defer unlocked.Wipe()

	restoredVault, err := restored.GetVault(ctx, "backup-drill")
	if err != nil {
		t.Fatal(err)
	}
	restoredCredential, err := restored.GetCredential(ctx, restoredVault.ID, "API_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := vaultcrypto.Decrypt(restoredCredential.Ciphertext, restoredCredential.Nonce, unlocked.Key())
	if err != nil || !bytes.Equal(plaintext, []byte("restored-secret")) {
		t.Fatalf("restored credential unusable: %v", err)
	}
	vaultcrypto.WipeBytes(plaintext)
	sources, err := restored.ListCredentialSources(ctx, restoredVault.ID)
	if err != nil || len(sources) != 1 || !store.CredentialSourceUsable(&sources[0], time.Now().UTC()) {
		t.Fatalf("restored credential sources unusable: %#v, %v", sources, err)
	}
	restoredOwner, err := restored.GetAgentBySPIFFEID(ctx, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := restored.ListActorGrants(ctx, restoredOwner.ID)
	hasDrillGrant := false
	for _, grant := range grants {
		if grant.VaultID == restoredVault.ID && grant.Role == "admin" {
			hasDrillGrant = true
		}
	}
	if err != nil || len(grants) < 2 || !hasDrillGrant {
		t.Fatalf("restored grants = %#v, %v", grants, err)
	}
	if broker, err := restored.GetBrokerConfig(ctx, restoredVault.ID); err != nil || !strings.Contains(broker.ServicesJSON, "api.example.com") {
		t.Fatalf("restored broker config = %#v, %v", broker, err)
	}
	logs, err := restored.ListRequestLogs(ctx, store.ListRequestLogsOpts{VaultID: &restoredVault.ID, Limit: 10})
	if err != nil || len(logs) != 1 || logs[0].Host != "api.example.com" {
		t.Fatalf("restored audit logs = %#v, %v", logs, err)
	}
	restoredCA, err := ca.New(unlocked.Key(), ca.Options{Store: &caStoreAdapter{db: restored}})
	if err != nil || !bytes.Equal(restoredCA.RootPEM(), sourceRoot) {
		t.Fatalf("restored CA is unusable or changed: %v", err)
	}
	if _, err := restoredCA.MintLeaf("api.example.com"); err != nil {
		t.Fatalf("restored CA cannot mint a leaf: %v", err)
	}

	replacement := &commandTestWrapper{identity: keywrap.Identity{Provider: "test-kms", KeyID: "recovered-primary"}}
	if err := performKeyRecovery(ctx, restored, recoveryWrapper, replacement, []byte(ageIdentity.String()), restoredOwner, ownerID); err != nil {
		t.Fatalf("explicit offline recovery failed: %v", err)
	}
	newPrimary, err := restoredPersistence.GetPrimaryDEKWrapping(ctx)
	if err != nil || newPrimary.KeyID != "recovered-primary" {
		t.Fatalf("recovered primary = %#v, %v", newPrimary, err)
	}
	recoveryEvents, err := restored.(store.KeyRecoveryStore).ListKeyRecoveryEvents(ctx, 10)
	if err != nil || len(recoveryEvents) != 1 || recoveryEvents[0].ActorSPIFFEID != ownerID {
		t.Fatalf("recovery audit = %#v, %v", recoveryEvents, err)
	}
	wrappings, err := restoredPersistence.ListDEKWrappings(ctx, false)
	if err != nil || len(wrappings) < 3 {
		t.Fatalf("restored wrappings = %#v, %v", wrappings, err)
	}
	vaults, err := restored.ListVaults(ctx)
	if err != nil {
		t.Fatal(err)
	}

	report := backupDrillReport{
		BackupDurationMS:      backupCompleted.Sub(backupStarted).Milliseconds(),
		ObservedSnapshotLagMS: backupStarted.Sub(lastWrite).Milliseconds(),
		RestoreRecoveryMS:     time.Since(restoreStarted).Milliseconds(),
		Vaults:                len(vaults),
		CredentialSources:     len(sources),
		Grants:                len(grants),
		RequestAuditRows:      len(logs),
		DEKWrappings:          len(wrappings),
		RecoveryAuditRows:     len(recoveryEvents),
		PrimaryProvider:       newPrimary.Provider,
		CAUsable:              true,
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if reportPath := os.Getenv("AGENT_VAULT_BACKUP_DRILL_REPORT"); reportPath != "" {
		if err := os.WriteFile(reportPath, append(reportJSON, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("backup/restore RPO-RTO observation: %s", reportJSON)
}

func openBackupDrillStore(t *testing.T, databaseURL string) store.Store {
	t.Helper()
	database, err := store.OpenStore(store.StoreConfig{
		DatabaseURL: databaseURL, MaxOpenConns: 10, MaxIdleConns: 2,
		ConnMaxLifetime: 5 * time.Minute, ConnectTimeout: 10 * time.Second, PoolConfigured: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func runPostgresTool(t *testing.T, ctx context.Context, databaseURL, tool string, extra ...string) {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	port := parsed.Port()
	if port == "" {
		port = "5432"
	}
	args := []string{"--host", parsed.Hostname(), "--port", port, "--username", parsed.User.Username()}
	args = append(args, extra...)
	command := exec.CommandContext(ctx, tool, args...)
	command.Env = append(os.Environ(), "PGPASSWORD="+postgresPassword(parsed), "PGSSLMODE="+postgresSSLMode(parsed))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v: %s", tool, err, output)
	}
}

func postgresDatabaseName(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(parsed.Path, "/")
	if name == "" || strings.Contains(name, "/") {
		t.Fatalf("invalid PostgreSQL database name")
	}
	return name
}

func postgresPassword(parsed *url.URL) string {
	if parsed.User == nil {
		return ""
	}
	password, _ := parsed.User.Password()
	return password
}

func postgresSSLMode(parsed *url.URL) string {
	if mode := parsed.Query().Get("sslmode"); mode != "" {
		return mode
	}
	return "prefer"
}

func timePointer(value time.Time) *time.Time { return &value }
