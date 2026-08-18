package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// loadServerConfig is the single configuration boundary for server startup.
// Runtime code receives the validated result and does not re-read flags or the
// environment.
func loadServerConfig(cmd *cobra.Command) (runtimeconfig.Result, error) {
	var flags runtimeconfig.Partial
	var flagSecrets runtimeconfig.FlagSecrets

	if cmd.Flags().Changed("host") {
		v, _ := cmd.Flags().GetString("host")
		flags.Server.Host = &v
	}
	if cmd.Flags().Changed("port") {
		v, _ := cmd.Flags().GetInt("port")
		flags.Server.Port = &v
	}
	if cmd.Flags().Changed("mitm-port") {
		v, _ := cmd.Flags().GetInt("mitm-port")
		flags.Server.ProxyPort = &v
	}
	if cmd.Flags().Changed("detach") {
		v, _ := cmd.Flags().GetBool("detach")
		flags.Server.Detach = &v
	}
	if cmd.Flags().Changed("log-level") {
		v, _ := cmd.Flags().GetString("log-level")
		flags.Server.LogLevel = &v
	}
	if cmd.Flags().Changed("max-response-bytes") {
		v, _ := cmd.Flags().GetInt64("max-response-bytes")
		flags.Proxy.MaxResponseBytes = &v
	}
	if cmd.Flags().Changed("max-request-bytes") {
		v, _ := cmd.Flags().GetInt64("max-request-bytes")
		flags.Proxy.MaxRequestBytes = &v
	}
	if cmd.Flags().Changed("database-url") {
		v, _ := cmd.Flags().GetString("database-url")
		secret := runtimeconfig.NewSecretValue([]byte(v))
		flagSecrets.DatabaseURL = &secret
	}
	if f := cmd.Flags().Lookup("telemetry"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetBool("telemetry")
		flags.Telemetry.Enabled = &v
	}

	path := ""
	if cmd.Flags().Changed("config") {
		path, _ = cmd.Flags().GetString("config")
	}
	return runtimeconfig.Load(runtimeconfig.Options{
		Path:        path,
		Flags:       flags,
		FlagSecrets: flagSecrets,
	})
}

func resetServerFlagChanges(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(flag *pflag.Flag) { flag.Changed = false })
}

func resolvedLogLevel(value string) slog.Level {
	if value == "debug" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func resolvedBaseURL(cfg runtimeconfig.Runtime, addr string) string {
	if cfg.Server.ExternalAddress != "" {
		return cfg.Server.ExternalAddress
	}
	return "http://" + addr
}

func resolvedSMTP(cfg runtimeconfig.SMTP) *notify.SMTPConfig {
	if strings.TrimSpace(cfg.Host) == "" || strings.TrimSpace(cfg.From) == "" {
		return nil
	}
	return &notify.SMTPConfig{
		Host: cfg.Host, Port: cfg.Port, Username: cfg.Username,
		Password: cfg.Password.RevealString(), From: cfg.From, FromName: cfg.FromName,
		TLSMode: cfg.TLSMode, TLSSkipVerify: cfg.TLSSkipVerify,
	}
}

func resolvedServerOptions(cfg runtimeconfig.Runtime) server.RuntimeOptions {
	rl, masks := ratelimit.LoadResolved(ratelimit.Profile(cfg.RateLimit.Profile), cfg.RateLimit.Locked)
	return server.RuntimeOptions{
		RateLimit:          rl,
		RateLimitEnvMasks:  masks,
		AllowPrivateRanges: cfg.Proxy.AllowPrivateRanges,
		NetworkAllowlist:   parseNetworkList(cfg.Proxy.NetworkAllowlist, "proxy.network_allowlist"),
		TrustedProxies:     parseNetworkList(cfg.Proxy.TrustedProxies, "proxy.trusted_proxies"),
		AuthMode:           cfg.Auth.Mode,
		MetricsEnabled:     cfg.Telemetry.MetricsEnabled,
	}
}

func parseNetworkList(values []string, label string) []net.IPNet {
	return netguard.ParseCIDRList(strings.Join(values, ","), label)
}

func clearResolvedSecretEnvironment(cfg runtimeconfig.Runtime) error {
	var failures []string
	names := map[string]struct{}{
		"DATABASE_URL": {}, "AGENT_VAULT_MASTER_PASSWORD": {}, "AGENT_VAULT_SMTP_PASSWORD": {},
	}
	for _, value := range []runtimeconfig.SecretValue{
		cfg.Database.URL, cfg.Encryption.LegacyMasterPassword, cfg.SMTP.Password,
	} {
		if ref := value.Ref().String(); strings.HasPrefix(ref, "env://") {
			names[strings.TrimPrefix(ref, "env://")] = struct{}{}
		}
	}
	for name := range names {
		if err := os.Unsetenv(name); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("clearing resolved secret environment: %s", strings.Join(failures, "; "))
	}
	return nil
}
