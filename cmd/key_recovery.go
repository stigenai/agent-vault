package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Infisical/agent-vault/internal/auth"
	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/keywrap/agerecovery"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
)

var keyRecoveryCmd = &cobra.Command{
	Use:   "key-recovery",
	Short: "Explicitly recover provider-wrapped encryption keys",
}

var keyRecoveryRunCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover the DEK and establish the configured provider primary",
	Args:  cobra.NoArgs,
	RunE:  runKeyRecovery,
}

var keyRecoveryHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List secret-free key recovery audit events",
	Args:  cobra.NoArgs,
	RunE:  runKeyRecoveryHistory,
}

type recoveryRuntime struct {
	config   runtimeconfig.Runtime
	db       store.Store
	source   *workloadidentity.Source
	actor    *store.Agent
	spiffeID string
}

func runKeyRecovery(cmd *cobra.Command, _ []string) error {
	confirmed, _ := cmd.Flags().GetBool("confirm-recovery")
	if !confirmed {
		return errors.New("explicit recovery requires --confirm-recovery")
	}
	recoveryName, _ := cmd.Flags().GetString("recovery-wrapper")
	newPrimaryName, _ := cmd.Flags().GetString("new-primary")
	identityPath, _ := cmd.Flags().GetString("identity-file")

	runtime, err := openRecoveryRuntime(commandContext(cmd), recoveryConfigPath(cmd))
	if err != nil {
		return err
	}
	defer runtime.close()
	if newPrimaryName != runtime.config.Encryption.PrimaryWrapper {
		return fmt.Errorf("--new-primary must equal encryption.primary_wrapper %q in the active configuration", runtime.config.Encryption.PrimaryWrapper)
	}
	recoveryConfig, ok := wrapperConfigByName(runtime.config.Encryption.Wrappers, recoveryName)
	if !ok || recoveryConfig.Kind != "age-x25519" {
		return fmt.Errorf("recovery wrapper %q must name a configured age-x25519 wrapper", recoveryName)
	}
	primaryConfig, ok := wrapperConfigByName(runtime.config.Encryption.Wrappers, newPrimaryName)
	if !ok || primaryConfig.Kind == "age-x25519" {
		return fmt.Errorf("new primary %q must name a configured provider wrapper", newPrimaryName)
	}
	wrappers, err := buildConfiguredWrappers(commandContext(cmd), []runtimeconfig.KeyWrapperConfig{recoveryConfig, primaryConfig}, runtime.source, runtime.config.Auth.TrustDomains)
	if err != nil {
		return err
	}
	identityText, err := readRecoveryIdentity(cmd, identityPath)
	if err != nil {
		return err
	}
	defer vaultcrypto.WipeBytes(identityText)
	if err := performKeyRecovery(commandContext(cmd), runtime.db, wrappers[recoveryName], wrappers[newPrimaryName], identityText, runtime.actor, runtime.spiffeID); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s Recovery verified; %q is now the audited primary wrapper.\n", successText("✓"), newPrimaryName)
	return nil
}

func performKeyRecovery(ctx context.Context, db store.Store, recoveryWrapper, newPrimary keywrap.KeyWrapper, identityText []byte, actor *store.Agent, actorSPIFFEID string) error {
	if actor == nil || actor.Role != "owner" || actor.Status != "active" || actor.SPIFFEID != actorSPIFFEID {
		return errors.New("key recovery requires an active SPIFFE instance owner")
	}
	persistence, ok := db.(store.KeyRecoveryStore)
	if !ok {
		return errors.New("key recovery requires recovery-capable storage")
	}
	if recoveryWrapper == nil || recoveryWrapper.Identity().Provider != "age-x25519" {
		return errors.New("explicit recovery requires an age-x25519 wrapper")
	}
	if newPrimary == nil || newPrimary.Identity().Provider == "age-x25519" {
		return errors.New("recovery must establish a provider-backed primary")
	}
	binding, err := keywrap.EnsureInstanceBinding(ctx, persistence)
	if err != nil {
		return err
	}
	recoveryRecord, err := findConfiguredRecoveryWrapping(ctx, persistence, recoveryWrapper.Identity())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("configured age recovery wrapping is not present in storage")
		}
		return err
	}
	dek, err := agerecovery.Recover(keywrap.WrappedDEK{
		Ciphertext: recoveryRecord.WrappedDEK,
		KeyVersion: recoveryRecord.KeyVersion,
	}, identityText, binding)
	if err != nil {
		return fmt.Errorf("recover DEK with selected age identity: %w", err)
	}
	defer vaultcrypto.WipeBytes(dek)
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return err
	}
	masterKey, err := auth.UnlockWithDEK(dek, buildVerificationRecord(record))
	if err != nil {
		return errors.New("recovered DEK failed instance verification")
	}
	defer masterKey.Wipe()
	if _, err := keywrap.EnsureRecoveryPrimary(ctx, persistence, newPrimary, masterKey.Key(), binding, store.KeyRecoveryEvent{
		ActorID:            actor.ID,
		ActorSPIFFEID:      actorSPIFFEID,
		RecoveryWrappingID: recoveryRecord.ID,
	}); err != nil {
		return fmt.Errorf("establish recovered primary wrapping: %w", err)
	}
	return nil
}

func findConfiguredRecoveryWrapping(ctx context.Context, persistence store.KeyWrappingStore, identity keywrap.Identity) (*store.DEKWrappingRecord, error) {
	records, err := persistence.ListDEKWrappings(ctx, false)
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].Provider == identity.Provider && records[i].KeyID == identity.KeyID {
			return &records[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

func openRecoveryRuntime(ctx context.Context, path string) (*recoveryRuntime, error) {
	result, err := runtimeconfig.Load(runtimeconfig.Options{Path: path})
	if err != nil {
		return nil, err
	}
	cfg := result.Config
	databaseURL := cfg.Database.URL.RevealString()
	db, err := store.OpenStore(store.StoreConfig{
		DatabaseURL: databaseURL, SQLitePath: cfg.Database.SQLitePath,
		MaxOpenConns: cfg.Database.MaxOpenConns, MaxIdleConns: cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime, PoolConfigured: true,
	})
	cfg.Database.URL.Wipe()
	cfg.Encryption.LegacyMasterPassword.Wipe()
	cfg.SMTP.Password.Wipe()
	if err != nil {
		return nil, fmt.Errorf("opening recovery store: %w", err)
	}
	source, err := workloadidentity.New(ctx, workloadidentity.Options{Address: cfg.Auth.WorkloadAPI})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("authorize key recovery with SPIFFE: %w", err)
	}
	id, err := source.ID()
	if err != nil {
		_ = source.Close()
		_ = db.Close()
		return nil, err
	}
	agent, err := db.GetAgentBySPIFFEID(ctx, id.String())
	if err != nil {
		_ = source.Close()
		_ = db.Close()
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("look up SPIFFE recovery actor: %w", err)
		}
		return nil, errors.New("key recovery requires the current SPIFFE ID to be an active instance owner")
	}
	if agent == nil || agent.Role != "owner" || agent.Status != "active" {
		_ = source.Close()
		_ = db.Close()
		return nil, errors.New("key recovery requires the current SPIFFE ID to be an active instance owner")
	}
	return &recoveryRuntime{config: cfg, db: db, source: source, actor: agent, spiffeID: id.String()}, nil
}

func (r *recoveryRuntime) close() {
	if r == nil {
		return
	}
	if r.source != nil {
		_ = r.source.Close()
	}
	if r.db != nil {
		_ = r.db.Close()
	}
}

func runKeyRecoveryHistory(cmd *cobra.Command, _ []string) error {
	runtime, err := openRecoveryRuntime(commandContext(cmd), recoveryConfigPath(cmd))
	if err != nil {
		return err
	}
	defer runtime.close()
	audit, ok := runtime.db.(store.KeyRecoveryStore)
	if !ok {
		return errors.New("key recovery history requires recovery-capable storage")
	}
	limit, _ := cmd.Flags().GetInt("limit")
	events, err := audit.ListKeyRecoveryEvents(commandContext(cmd), limit)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tACTOR SPIFFE ID\tRECOVERY WRAPPER\tNEW PRIMARY")
	for _, event := range events {
		fmt.Fprintf(w, "%s\t%s\t%s/%s\t%s/%s@%s\n", event.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			event.ActorSPIFFEID, event.RecoveryProvider, event.RecoveryKeyID,
			event.NewPrimaryProvider, event.NewPrimaryKeyID, event.NewPrimaryKeyVersion)
	}
	return w.Flush()
}

func readRecoveryIdentity(cmd *cobra.Command, path string) ([]byte, error) {
	var reader io.Reader
	var file *os.File
	if path == "-" {
		reader = cmd.InOrStdin()
	} else {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open recovery identity: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, errors.New("inspect recovery identity failed")
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("recovery identity must be a regular file readable only by its owner (mode 0600 or stricter)")
		}
		reader = file
	}
	identity, err := io.ReadAll(io.LimitReader(reader, 8193))
	if err != nil {
		return nil, errors.New("read recovery identity failed")
	}
	if len(identity) == 0 || len(identity) > 8192 {
		vaultcrypto.WipeBytes(identity)
		return nil, errors.New("recovery identity must be between 1 and 8192 bytes")
	}
	return identity, nil
}

func wrapperConfigByName(configs []runtimeconfig.KeyWrapperConfig, name string) (runtimeconfig.KeyWrapperConfig, bool) {
	for _, config := range configs {
		if config.Name == name {
			return config, true
		}
	}
	return runtimeconfig.KeyWrapperConfig{}, false
}

func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func recoveryConfigPath(cmd *cobra.Command) string {
	path, _ := cmd.Flags().GetString("config")
	return strings.TrimSpace(path)
}

func init() {
	keyRecoveryRunCmd.Flags().String("config", "", "path to the active server TOML")
	keyRecoveryRunCmd.Flags().String("recovery-wrapper", "", "configured age-x25519 recovery wrapper name")
	keyRecoveryRunCmd.Flags().String("new-primary", "", "configured provider wrapper to establish as primary")
	keyRecoveryRunCmd.Flags().String("identity-file", "", "age X25519 private identity file, or - for stdin")
	keyRecoveryRunCmd.Flags().Bool("confirm-recovery", false, "confirm explicit offline key recovery")
	_ = keyRecoveryRunCmd.MarkFlagRequired("recovery-wrapper")
	_ = keyRecoveryRunCmd.MarkFlagRequired("new-primary")
	_ = keyRecoveryRunCmd.MarkFlagRequired("identity-file")
	keyRecoveryHistoryCmd.Flags().String("config", "", "path to the active server TOML")
	keyRecoveryHistoryCmd.Flags().Int("limit", 50, "maximum events to show (1-200)")
	keyRecoveryCmd.AddCommand(keyRecoveryRunCmd, keyRecoveryHistoryCmd)
	ownerCmd.AddCommand(keyRecoveryCmd)
}
