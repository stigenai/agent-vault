package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/ca"
	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/telemetry"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const maxPasswordAttempts = 3

// resolveLogLevel turns the --log-level flag (or AGENT_VAULT_LOG_LEVEL env
// fallback) into a slog.Level. Flag wins if explicitly set. Accepts "info"
// and "debug" only — anything else is rejected with a clear error.
// flagChanged indicates whether the user passed --log-level explicitly.
func resolveLogLevel(flagValue string, flagChanged bool) (slog.Level, error) {
	value := flagValue
	if !flagChanged {
		if env := os.Getenv("AGENT_VAULT_LOG_LEVEL"); env != "" {
			value = env
		}
	}
	switch strings.ToLower(value) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (accepted: info, debug)", value)
	}
}

// resolveBaseURL returns the externally-reachable base URL for the server.
// Priority: AGENT_VAULT_ADDR env var > FLY_APP_NAME-derived URL > http://{addr}.
func resolveBaseURL(addr string) string {
	if v := os.Getenv("AGENT_VAULT_ADDR"); v != "" {
		return v
	}
	if app := os.Getenv("FLY_APP_NAME"); app != "" {
		return "https://" + app + ".fly.dev"
	}
	return "http://" + addr
}

// buildLogger constructs the process-wide slog logger. Text handler to
// stderr keeps it readable in a terminal without a dependency bump.
func buildLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start an Agent Vault server",
	RunE: func(cmd *cobra.Command, args []string) error {
		defer resetServerFlagChanges(cmd)
		isDetachedChild := os.Getenv("_AGENT_VAULT_DETACHED") == "1"
		if !isDetachedChild {
			// Preserve the cheap legacy pre-flight before configuration or
			// secret resolution.
			if pid, err := pidfile.Read(); err == nil {
				if pid != os.Getpid() && pidfile.IsRunning(pid) {
					return fmt.Errorf("server is already running (PID %d). Use 'agent-vault server stop' to stop it first", pid)
				}
				_ = pidfile.Remove()
			}
		}
		resolved, err := loadServerConfig(cmd)
		if err != nil {
			return err
		}
		cfg := resolved.Config
		port := cfg.Server.Port
		host := cfg.Server.Host
		detach := cfg.Server.Detach
		mitmPort := cfg.Server.ProxyPort
		addr := net.JoinHostPort(host, strconv.Itoa(port))

		logger := buildLogger(resolvedLogLevel(cfg.Server.LogLevel))

		// --- Detached child path: read master key + initialized flag from stdin pipe ---
		if isDetachedChild {
			if err := clearResolvedSecretEnvironment(cfg); err != nil {
				return err
			}
			return runDetachedChild(cfg, addr, logger)
		}
		if !detach {
			if err := clearResolvedSecretEnvironment(cfg); err != nil {
				return err
			}
		}

		dbURL := cfg.Database.URL.RevealString()
		dbPath := cfg.Database.SQLitePath

		db, err := store.OpenStore(store.StoreConfig{
			DatabaseURL: dbURL, SQLitePath: dbPath,
			MaxOpenConns: cfg.Database.MaxOpenConns, MaxIdleConns: cfg.Database.MaxIdleConns,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime, ConnectTimeout: cfg.Database.ConnectTimeout,
			TLSMode: cfg.Database.TLSMode, TLSRootCert: cfg.Database.TLSRootCert, PoolConfigured: true,
		})
		if err != nil {
			return fmt.Errorf("opening store: %w", err)
		}
		defer func() { _ = db.Close() }()

		if dbURL != "" {
			if n, _ := db.CountUsers(context.Background()); n == 0 {
				if sqlitePath, err2 := store.DefaultDBPath(); err2 == nil {
					if _, err2 := os.Stat(sqlitePath); err2 == nil {
						fmt.Fprintln(cmd.OutOrStderr(),
							"warning: DATABASE_URL is set but the Postgres database has no users.",
							"If you have existing data in SQLite, run 'agent-vault migrate-db --to <url>' first.",
						)
					}
				}
			}
		}
		if !detach {
			cfg.Database.URL.Wipe()
		}
		identitySource, listenerTLS, proxyTLS, err := configureWorkloadIdentity(context.Background(), cfg, db)
		if err != nil {
			return err
		}
		if identitySource != nil {
			defer func() { _ = identitySource.Close() }()
		}

		passwordStdin, _ := cmd.Flags().GetBool("password-stdin")
		interactive := !passwordStdin && !cfg.Encryption.LegacyMasterPassword.IsSet()

		masterKey, err := unlockOrSetupWithConfiguredWrappers(cmd, db, passwordStdin, cfg.Encryption, identitySource, cfg.Auth.TrustDomains)
		cfg.Encryption.LegacyMasterPassword.Wipe()
		if err != nil {
			return err
		}

		// Claim SPIFFE bootstrap before listening. The database marker makes this
		// safe across concurrently starting Kubernetes replicas.
		ctx := context.Background()
		if cfg.Auth.Mode == "spiffe" {
			bootstrap, err := db.BootstrapSPIFFEOwners(ctx, cfg.Auth.BootstrapOwnerIDs)
			if err != nil {
				masterKey.Wipe()
				return fmt.Errorf("bootstrap SPIFFE owners: %w", err)
			}
			if bootstrap.OwnerCount == 0 {
				masterKey.Wipe()
				return fmt.Errorf("SPIFFE owner bootstrap was already consumed but no active owner remains")
			}
			if bootstrap.SPIFFEOwners == 0 {
				masterKey.Wipe()
				return fmt.Errorf("SPIFFE-only mode requires an active SPIFFE owner; create one in hybrid mode before switching")
			}
			if !bootstrap.Applied && !sameStringSet(bootstrap.ConfiguredIDs, cfg.Auth.BootstrapOwnerIDs) {
				logger.Warn("configured SPIFFE bootstrap owners differ from the immutable database claim; changes were ignored")
			}
		}
		ownerCount, err := db.CountAllOwners(ctx)
		if err != nil {
			masterKey.Wipe()
			return fmt.Errorf("checking owner count: %w", err)
		}
		initialized := ownerCount > 0

		if !initialized && interactive && cfg.Auth.Mode != "spiffe" {
			if err := promptOwnerSetup(cmd, db, nil); err != nil {
				masterKey.Wipe()
				return err
			}
			initialized = true
		}

		if detach {
			return spawnDetached(cmd, masterKey, initialized, cfg, addr)
		}

		// --- Foreground path ---
		defer masterKey.Wipe()
		baseURL := resolvedBaseURL(cfg, addr)
		smtpCfg := resolvedSMTP(cfg.SMTP)
		cfg.SMTP.Password.Wipe()
		notifier := notify.New(smtpCfg)
		serverOpts := resolvedServerOptions(cfg)
		serverOpts.TLSConfig = listenerTLS
		srv := server.NewWithRuntime(addr, db, masterKey.Key(), notifier, initialized, baseURL, logger, serverOpts)
		if identitySource != nil {
			srv.AttachReadinessCheck("workload identity unavailable", func(context.Context) error {
				return identitySource.Ready()
			})
			srv.AttachMetricsIdentity(identitySource)
		}
		srv.SetSkills(skillCLI)
		if cfg.Telemetry.Enabled {
			srv.AttachTelemetry(tel)
		}
		shutdownLogs := attachLogSink(srv, db, logger, cfg.Logs)
		defer shutdownLogs()
		if err := attachServerExtensions(srv, cfg, masterKey.Key(), db, logger, proxyTLS, identitySource); err != nil {
			return err
		}
		if cfg.Telemetry.Enabled {
			captureServerStart(mitmPort, db.DialectName())
		}
		return srv.Start()
	},
}

// attachMITMIfEnabled initializes the CA and attaches a transparent MITM
// proxy to srv when mitmPort > 0. The CA is loaded or created under the
// standard ~/.agent-vault/ca/ directory, encrypted with the master key.
//
// CA init failures are non-fatal, matching the behavior for bind failures
// in server.Start: since the MITM proxy is default-on, environments that
// cannot create ~/.agent-vault/ca/ (read-only FS, containers without HOME,
// corrupted state) must still be able to run the core HTTP server.
func configureWorkloadIdentity(ctx context.Context, cfg runtimeconfig.Runtime, db store.Store) (*workloadidentity.Source, *tls.Config, *tls.Config, error) {
	if cfg.Auth.Mode == "legacy" {
		return nil, nil, nil, nil
	}
	domains := make([]spiffeid.TrustDomain, 0, len(cfg.Auth.TrustDomains))
	for _, raw := range cfg.Auth.TrustDomains {
		domain, err := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse auth trust domain %q: %w", raw, err)
		}
		domains = append(domains, domain)
	}
	source, err := workloadidentity.New(ctx, workloadidentity.Options{Address: cfg.Auth.WorkloadAPI})
	if err != nil {
		return nil, nil, nil, err
	}
	authorizer := workloadidentity.AuthorizeAgents(db, domains...)
	// The API requests (but does not handshake-require) a client SVID so
	// unauthenticated /health remains usable by Kubernetes probes. Protected
	// routes enforce SPIFFE-only mode in middleware.
	listenerTLS, err := source.HybridServerTLSConfig(authorizer)
	if err != nil {
		_ = source.Close()
		return nil, nil, nil, fmt.Errorf("configure SPIFFE API listener: %w", err)
	}
	var proxyTLS *tls.Config
	if cfg.Auth.Mode == "spiffe" {
		proxyTLS, err = source.ServerTLSConfig(authorizer)
		if err != nil {
			_ = source.Close()
			return nil, nil, nil, fmt.Errorf("configure SPIFFE proxy listener: %w", err)
		}
	}
	return source, listenerTLS, proxyTLS, nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}

func attachMITMIfEnabled(srv *server.Server, cfg runtimeconfig.Runtime, masterKey []byte, db store.Store, proxyTLS *tls.Config) error {
	host, mitmPort := cfg.Server.Host, cfg.Server.ProxyPort
	if mitmPort <= 0 {
		return nil
	}
	var extraSANs []string
	if u, err := url.Parse(srv.BaseURL()); err == nil {
		if h := u.Hostname(); h != "" {
			extraSANs = []string{h}
		}
	}
	caOpts := ca.Options{ExtraSANs: extraSANs}
	if db.DialectName() == "postgres" {
		caOpts.Store = &caStoreAdapter{db: db}
	}
	caProv, err := ca.New(masterKey, caOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: transparent proxy disabled (CA init failed: %v); pass --mitm-port 0 to suppress\n", err)
		return nil
	}
	srv.AttachMITM(mitm.New(
		net.JoinHostPort(host, strconv.Itoa(mitmPort)),
		mitm.Options{
			CA:                      caProv,
			Sessions:                srv.SessionResolver(),
			Peers:                   srv.AgentResolver(),
			Agents:                  db,
			Credentials:             srv.CredentialProvider(),
			BaseURL:                 srv.BaseURL(),
			Logger:                  srv.Logger(),
			RateLimit:               srv.RateLimit(),
			LogSink:                 srv.LogSink(),
			MaxResponseBytes:        cfg.Proxy.MaxResponseBytes,
			MaxRequestBytes:         cfg.Proxy.MaxRequestBytes,
			AllowPrivateRanges:      cfg.Proxy.AllowPrivateRanges,
			NetworkAllowlist:        parseNetworkList(cfg.Proxy.NetworkAllowlist, "proxy.network_allowlist"),
			NetworkPolicyConfigured: true,
			TLSConfig:               proxyTLS,
			SPIFFEOnly:              cfg.Auth.Mode == "spiffe",
		},
	))
	return nil
}

// attachServerExtensions wires optional subsystems (MITM, Infisical) onto srv.
// Both bootstrap paths (foreground and detached child) call this.
func attachServerExtensions(srv *server.Server, cfg runtimeconfig.Runtime, masterKey []byte, db store.Store, logger *slog.Logger, proxyTLS *tls.Config, identitySource *workloadidentity.Source) error {
	if err := attachMITMIfEnabled(srv, cfg, masterKey, db, proxyTLS); err != nil {
		return err
	}
	infisicalClient := attachInfisicalIfConfigured(srv, logger)
	return attachSecretProviders(srv, cfg, masterKey, db, logger, identitySource, infisicalClient)
}

// attachInfisicalIfConfigured wires the Infisical client when INFISICAL_URL
// is set. The 10s deadline uses time.After because the SDK login is
// synchronous and ignores ctx; on timeout we proceed without a client so
// external vaults serve-stale until next restart.
func attachInfisicalIfConfigured(srv *server.Server, logger *slog.Logger) *infisical.Client {
	if os.Getenv("INFISICAL_URL") == "" {
		return nil
	}
	type result struct {
		c   *infisical.Client
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := infisical.NewClient(context.Background(), logger)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			logger.Warn("infisical client unavailable; external-store vaults will not refresh",
				slog.String("err", r.err.Error()))
			return nil
		}
		srv.AttachInfisical(r.c)
		return r.c
	case <-time.After(10 * time.Second):
		logger.Warn("infisical client login exceeded 10s deadline; continuing without external store")
	}
	return nil
}

// attachLogSink wires the request-log pipeline: a BatchSink with async
// batching feeds persistent storage, and a retention goroutine trims old
// rows. Returns a shutdown function the caller runs after Start()
// returns to flush pending records and stop retention.
func attachLogSink(srv *server.Server, db store.Store, logger *slog.Logger, cfg runtimeconfig.Logs) func() {
	sink := requestlog.NewBatchSink(db, logger, requestlog.BatchSinkConfig{})
	srv.AttachLogSink(sink)

	retentionCtx, cancelRetention := context.WithCancel(context.Background())
	go requestlog.RunRetentionConfigured(retentionCtx, db, logger, requestlog.RetentionConfig{
		MaxAge: cfg.MaxAge, MaxRowsPerVault: cfg.MaxRowsPerVault,
	}, cfg.RetentionLocked)

	return func() {
		cancelRetention()
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sink.Close(flushCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: request_log sink flush: %v\n", err)
		}
	}
}

// promptOwnerSetup interactively creates the owner account.
// masterPassword is optional — if provided, the admin password is checked against it.
func promptOwnerSetup(cmd *cobra.Command, db store.Store, masterPassword []byte) error {
	fmt.Fprintln(cmd.OutOrStderr(), boldText("Create owner account:"))

	email, err := auth.PromptEmail("  Admin email: ")
	if err != nil {
		return fmt.Errorf("email input: %w", err)
	}

	pw, err := auth.PromptNewPassword("  Admin password: ", "  Confirm admin password: ")
	if err != nil {
		return fmt.Errorf("password input: %w", err)
	}

	if len(pw) < 8 {
		return fmt.Errorf("admin password must be at least 8 characters")
	}

	if masterPassword != nil && string(pw) == string(masterPassword) {
		return fmt.Errorf("admin password must be different from the master password")
	}

	hash, salt, kdfP, err := auth.HashUserPassword(pw)
	crypto.WipeBytes(pw)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Get the default vault so the owner is granted admin access on it.
	vault, err := db.GetVault(context.Background(), "default")
	if err != nil {
		return fmt.Errorf("looking up default vault: %w", err)
	}

	if _, err := db.RegisterFirstUser(context.Background(), email, hash, salt, vault.ID, kdfP.Time, kdfP.Memory, kdfP.Threads); err != nil {
		return fmt.Errorf("creating owner account: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s Owner account created for %s\n", successText("✓"), email)
	return nil
}

// unlockOrSetup resolves the DEK from the already-resolved runtime config,
// then --password-stdin, then the interactive compatibility flow.
func unlockOrSetup(cmd *cobra.Command, db store.Store, passwordStdin bool, configuredPassword runtimeconfig.SecretValue) (*auth.MasterKey, error) {
	if configuredPassword.IsSet() {
		return unlockOrSetupWithPassword(db, configuredPassword.Bytes())
	}

	// --password-stdin (non-interactive, single attempt)
	if passwordStdin {
		password, err := readPasswordFromStdin()
		if err != nil {
			return nil, err
		}
		return unlockOrSetupWithPassword(db, password)
	}

	// Interactive prompt
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}

	if record == nil {
		// First-time setup — prompt with confirmation, allow empty for passwordless
		fmt.Fprintln(cmd.OutOrStderr(), boldText("Setting up for the first time."))
		pw, err := auth.PromptNewPassword(
			"Enter master password (leave empty for passwordless): ",
			"Confirm master password: ",
		)
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}
		return setupMasterKey(db, pw)
	}

	// Existing record — check if passwordless
	if record.DEKPlaintext != nil {
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return nil, fmt.Errorf("unlocking (passwordless): %w", err)
		}
		return mk, nil
	}

	// Password-protected — interactive unlock, up to 3 attempts
	verRec := buildVerificationRecord(record)
	fmt.Fprintln(cmd.OutOrStderr(), boldText("Agent Vault is locked. Enter master password to unlock."))

	for attempt := 1; attempt <= maxPasswordAttempts; attempt++ {
		password, err := auth.PromptPassword("Master password: ")
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}

		mk, err := auth.Unlock(password, verRec)
		crypto.WipeBytes(password)
		if err == nil {
			return mk, nil
		}

		if attempt < maxPasswordAttempts {
			fmt.Fprintf(cmd.OutOrStderr(), "%s Wrong password. %d attempt(s) remaining.\n", warningText("!"), maxPasswordAttempts-attempt)
		} else {
			return nil, fmt.Errorf("too many failed attempts")
		}
	}

	return nil, fmt.Errorf("too many failed attempts")
}

// unlockOrSetupWithPassword resolves the DEK using a known password (no prompting, no retry).
// Used by the AGENT_VAULT_MASTER_PASSWORD envvar and --password-stdin code paths.
func unlockOrSetupWithPassword(db store.Store, password []byte) (*auth.MasterKey, error) {
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}

	if record == nil {
		return setupMasterKey(db, password)
	}

	// Passwordless instance — password is ignored, unlock without it
	if record.DEKPlaintext != nil {
		crypto.WipeBytes(password)
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return nil, fmt.Errorf("unlocking (passwordless): %w", err)
		}
		return mk, nil
	}

	// Password-protected — single attempt, no retry
	verRec := buildVerificationRecord(record)
	mk, err := auth.Unlock(password, verRec)
	crypto.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("wrong password")
	}
	return mk, nil
}

// setupMasterKey runs first-time DEK generation and KEK wrapping.
// If password is empty, sets up in passwordless mode.
//
// In HA (Postgres), another pod may have already created the master key
// record. SetMasterKeyRecord uses ON CONFLICT DO NOTHING, so if the
// record already exists, we re-read it and unlock using the existing
// record instead of the locally-generated one.
func setupMasterKey(db store.Store, password []byte) (*auth.MasterKey, error) {
	var mk *auth.MasterKey
	var rec *auth.VerificationRecord
	var err error

	if len(password) == 0 {
		mk, rec, err = auth.SetupPasswordless()
	} else {
		mk, rec, err = auth.SetupWithPassword(password)
	}
	if err != nil {
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return nil, fmt.Errorf("setting up master key: %w", err)
	}

	ctx := context.Background()
	storeRec := verificationToStoreRecord(rec)
	if err := db.SetMasterKeyRecord(ctx, storeRec); err != nil {
		mk.Wipe()
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return nil, fmt.Errorf("persisting master key record: %w", err)
	}

	// Re-read the record: if another pod won the race (ON CONFLICT DO
	// NOTHING), the DB has THEIR record, not ours. We need to unlock
	// using whatever is actually stored.
	existing, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		mk.Wipe()
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return nil, fmt.Errorf("re-reading master key after setup: %w", err)
	}

	verRec := buildVerificationRecord(existing)
	if existing.DEKPlaintext != nil {
		mk.Wipe()
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return auth.UnlockPasswordless(verRec)
	}

	if len(password) > 0 {
		mk.Wipe()
		unlocked, err := auth.Unlock(password, verRec)
		crypto.WipeBytes(password)
		if err != nil {
			return nil, fmt.Errorf("unlocking with password after race: %w", err)
		}
		return unlocked, nil
	}

	// If we reach here, len(password) == 0 and existing.DEKPlaintext
	// was handled above (passwordless unlock). The only remaining case
	// is a password-protected DB record with no local password.
	mk.Wipe()
	return nil, fmt.Errorf("master key in database is password-protected but AGENT_VAULT_MASTER_PASSWORD is not set; all pods must use the same master password")
}

// verificationToStoreRecord converts an auth VerificationRecord to a store MasterKeyRecord.
func verificationToStoreRecord(rec *auth.VerificationRecord) *store.MasterKeyRecord {
	r := &store.MasterKeyRecord{
		Sentinel:      rec.Sentinel,
		SentinelNonce: rec.SentinelNonce,
		DEKCiphertext: rec.DEKCiphertext,
		DEKNonce:      rec.DEKNonce,
		DEKPlaintext:  rec.DEKPlaintext,
		Salt:          rec.Salt,
	}
	if rec.Params.Time > 0 {
		r.KDFTime = &rec.Params.Time
		r.KDFMemory = &rec.Params.Memory
		r.KDFThreads = &rec.Params.Threads
	}
	return r
}

// buildVerificationRecord converts a store record to an auth verification record.
func buildVerificationRecord(record *store.MasterKeyRecord) *auth.VerificationRecord {
	vr := &auth.VerificationRecord{
		Sentinel:      record.Sentinel,
		SentinelNonce: record.SentinelNonce,
		DEKCiphertext: record.DEKCiphertext,
		DEKNonce:      record.DEKNonce,
		DEKPlaintext:  record.DEKPlaintext,
		Salt:          record.Salt,
	}
	if record.KDFTime != nil {
		defaults := crypto.DefaultKDFParams()
		vr.Params = crypto.KDFParams{
			Time:    *record.KDFTime,
			Memory:  *record.KDFMemory,
			Threads: *record.KDFThreads,
			KeyLen:  defaults.KeyLen,
			SaltLen: defaults.SaltLen,
		}
	}
	return vr
}

// readPasswordFromStdin reads a single line from stdin for non-interactive password input.
func readPasswordFromStdin() ([]byte, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read password from stdin")
	}
	return []byte(strings.TrimRight(scanner.Text(), "\r\n")), nil
}

// runDetachedChild is the entry point for the detached child process.
// It reads 33 bytes from stdin: 32-byte master key + 1-byte initialized flag.
func runDetachedChild(cfg runtimeconfig.Runtime, addr string, logger *slog.Logger) error {
	cfg.Encryption.LegacyMasterPassword.Wipe()
	buf := make([]byte, 33)
	if _, err := io.ReadFull(os.Stdin, buf); err != nil {
		return fmt.Errorf("reading master key from pipe: %w", err)
	}
	key := buf[:32]
	initialized := buf[32] == 1

	dbURL := cfg.Database.URL.RevealString()

	db, err := store.OpenStore(store.StoreConfig{
		DatabaseURL: dbURL, SQLitePath: cfg.Database.SQLitePath,
		MaxOpenConns: cfg.Database.MaxOpenConns, MaxIdleConns: cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime, ConnectTimeout: cfg.Database.ConnectTimeout,
		TLSMode: cfg.Database.TLSMode, TLSRootCert: cfg.Database.TLSRootCert, PoolConfigured: true,
	})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	cfg.Database.URL.Wipe()
	defer func() { _ = db.Close() }()

	baseURL := resolvedBaseURL(cfg, addr)
	smtpCfg := resolvedSMTP(cfg.SMTP)
	cfg.SMTP.Password.Wipe()
	notifier := notify.New(smtpCfg)
	identitySource, listenerTLS, proxyTLS, err := configureWorkloadIdentity(context.Background(), cfg, db)
	if err != nil {
		return err
	}
	if identitySource != nil {
		defer func() { _ = identitySource.Close() }()
	}
	serverOpts := resolvedServerOptions(cfg)
	serverOpts.TLSConfig = listenerTLS
	srv := server.NewWithRuntime(addr, db, key, notifier, initialized, baseURL, logger, serverOpts)
	if identitySource != nil {
		srv.AttachReadinessCheck("workload identity unavailable", func(context.Context) error {
			return identitySource.Ready()
		})
		srv.AttachMetricsIdentity(identitySource)
	}
	srv.SetSkills(skillCLI)
	if cfg.Telemetry.Enabled {
		srv.AttachTelemetry(tel)
	}
	shutdownLogs := attachLogSink(srv, db, logger, cfg.Logs)
	defer shutdownLogs()
	if err := attachServerExtensions(srv, cfg, key, db, logger, proxyTLS, identitySource); err != nil {
		return err
	}
	if cfg.Telemetry.Enabled {
		captureServerStart(cfg.Server.ProxyPort, db.DialectName())
	}
	return srv.Start()
}

// spawnDetached re-execs the server as a background process, passing the
// master key and initialized flag through a private pipe and forwarding the
// resolved non-secret runtime flags.
func spawnDetached(cmd *cobra.Command, masterKey *auth.MasterKey, initialized bool, cfg runtimeconfig.Runtime, addr string) error {
	defer masterKey.Wipe()
	defer cfg.Database.URL.Wipe()
	defer cfg.SMTP.Password.Wipe()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating pipe: %w", err)
	}

	logPath, err := serverLogPath()
	if err != nil {
		return fmt.Errorf("resolving log path: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("opening log file: %w", err)
	}

	childArgs := []string{
		"server", "--port", strconv.Itoa(cfg.Server.Port), "--host", cfg.Server.Host,
		"--mitm-port", strconv.Itoa(cfg.Server.ProxyPort), "--log-level", cfg.Server.LogLevel,
		"--max-response-bytes", strconv.FormatInt(cfg.Proxy.MaxResponseBytes, 10),
		"--max-request-bytes", strconv.FormatInt(cfg.Proxy.MaxRequestBytes, 10),
	}
	if configPath, _ := cmd.Flags().GetString("config"); configPath != "" {
		childArgs = append(childArgs, "--config", configPath)
	}
	child := exec.Command(exe, childArgs...)
	child.Stdin = pr
	child.Stdout = logFile
	child.Stderr = logFile
	childEnv := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DATABASE_URL=") {
			continue
		}
		childEnv = append(childEnv, kv)
	}
	childEnv = append(childEnv, "_AGENT_VAULT_DETACHED=1")
	if dbURL := cfg.Database.URL.RevealString(); dbURL != "" {
		childEnv = append(childEnv, "DATABASE_URL="+dbURL)
	}
	child.Env = childEnv
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		_ = clearResolvedSecretEnvironment(cfg)
		_ = pr.Close()
		_ = pw.Close()
		_ = logFile.Close()
		return fmt.Errorf("starting detached server: %w", err)
	}
	if err := clearResolvedSecretEnvironment(cfg); err != nil {
		_ = child.Process.Kill()
		return err
	}

	// Send the master key + initialized flag (33 bytes) to the child via the pipe.
	var initByte byte
	if initialized {
		initByte = 1
	}
	payload := make([]byte, 33)
	copy(payload, masterKey.Key())
	payload[32] = initByte
	if _, err := pw.Write(payload); err != nil {
		crypto.WipeBytes(payload)
		_ = pw.Close()
		_ = pr.Close()
		_ = logFile.Close()
		return fmt.Errorf("sending master key to child: %w", err)
	}
	crypto.WipeBytes(payload)
	_ = pw.Close()
	_ = pr.Close()
	_ = logFile.Close()

	// Poll the health endpoint to verify the child started.
	healthURL := fmt.Sprintf("http://%s/health", addr)
	started := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				started = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if started {
		fmt.Fprintf(cmd.OutOrStdout(), "%s Server started in background (PID %d). Logs: %s\n",
			successText("✓"), child.Process.Pid, logPath)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStderr(), "%s Server may still be starting. Check %s for details.\n",
		warningText("!"), logPath)
	return fmt.Errorf("server did not respond within 3 seconds")
}

func serverLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agent-vault", "server.log"), nil
}

// --- Stop subcommand ---

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running Agent Vault server",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := pidfile.Read()
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("no server appears to be running (PID file not found)")
			}
			return fmt.Errorf("reading PID file: %w", err)
		}

		if !pidfile.IsRunning(pid) {
			_ = pidfile.Remove()
			return fmt.Errorf("server process %d is not running (stale PID file removed)", pid)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Stopping server (PID %d)...\n", pid)

		if err := stopServer(); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Server stopped.\n", successText("✓"))
		return nil
	},
}

func captureServerStart(mitmPort int, dbBackend string) {
	distinctID := telemetry.MachineID()
	if sess, _ := session.Load(); sess != nil && sess.Email != "" {
		distinctID = sess.Email
	}
	if distinctID == "" {
		distinctID = "anonymous_server"
	}
	tel.CaptureEvent(distinctID, "av.server-start", map[string]string{
		"mitm_enabled":     strconv.FormatBool(mitmPort > 0),
		"database_backend": dbBackend,
	})
}

func init() {
	serverCmd.Flags().String("config", "", "path to versioned server TOML (also respects AGENT_VAULT_CONFIG)")
	serverCmd.Flags().IntP("port", "p", defaultPort(), "port to listen on (also respects PORT env var)")
	serverCmd.Flags().String("host", DefaultHost, "host to bind to")
	serverCmd.Flags().String("database-url", "", "PostgreSQL connection URL (also respects DATABASE_URL env var)")
	serverCmd.Flags().BoolP("detach", "d", false, "run server in background after unlocking")
	serverCmd.Flags().Bool("password-stdin", false, "read master password from stdin (for non-interactive use)")
	serverCmd.Flags().Int("mitm-port", DefaultMITMPort, "port for the transparent MITM proxy (0 = disabled)")
	serverCmd.Flags().String("log-level", "info", "log level: info (default) or debug (per-request proxy logs)")
	serverCmd.Flags().Int64("max-response-bytes", defaultMaxResponseBytes(), "max response body bytes streamed to agents (default: unlimited; also respects AGENT_VAULT_MAX_RESPONSE_BYTES)")
	serverCmd.Flags().Int64("max-request-bytes", defaultMaxRequestBytes(), "max request body bytes forwarded to upstreams (default: 1 GiB; also respects AGENT_VAULT_MAX_REQUEST_BYTES)")
	serverCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(serverCmd)
}

// caStoreAdapter bridges store.Store to the ca.CAStore interface.
type caStoreAdapter struct {
	db store.Store
}

func (a *caStoreAdapter) GetCAState(ctx context.Context) (*ca.CAStateRecord, error) {
	state, err := a.db.GetCAState(ctx)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, nil
	}
	return &ca.CAStateRecord{
		RootCert:     state.RootCert,
		RootKeyCT:    state.RootKeyCT,
		RootKeyNonce: state.RootKeyNonce,
	}, nil
}

func (a *caStoreAdapter) SetCAState(ctx context.Context, rec *ca.CAStateRecord) error {
	return a.db.SetCAState(ctx, &store.CAState{
		RootCert:     rec.RootCert,
		RootKeyCT:    rec.RootKeyCT,
		RootKeyNonce: rec.RootKeyNonce,
		Source:       "auto",
	})
}
