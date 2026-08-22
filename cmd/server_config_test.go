package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/spf13/cobra"
)

func TestLoadServerConfigPreservesPrecedenceAndLiteralDatabaseFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	body := `schema_version = 1
[server]
host = "toml-host"
port = 24321
[database]
url = "env://TOML_DATABASE_URL"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_VAULT_CONFIG", path)
	t.Setenv("TOML_DATABASE_URL", "postgres://toml/db")
	t.Setenv("AGENT_VAULT_HOST", "env-host")

	cmd := newServerConfigTestCommand()
	if err := cmd.ParseFlags([]string{"--host", "flag-host", "--database-url", "postgres://flag-user:flag-secret@example/db"}); err != nil {
		t.Fatal(err)
	}
	result, err := loadServerConfig(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Server.Host != "flag-host" || result.Config.Server.Port != 24321 {
		t.Fatalf("resolved server config = %#v", result.Config.Server)
	}
	if got := result.Config.Database.URL.RevealString(); got != "postgres://flag-user:flag-secret@example/db" {
		t.Fatalf("database URL = %q", got)
	}
	if output := fmt.Sprintf("%#v", result.Config); strings.Contains(output, "flag-secret") {
		t.Fatalf("resolved config leaked database flag: %s", output)
	}
}

func TestResolvedServerOptionsUseTypedProfileAndLegacyTierOverrides(t *testing.T) {
	t.Setenv("AGENT_VAULT_RATELIMIT_PROFILE", "loose")
	t.Setenv("AGENT_VAULT_RATELIMIT_PROXY_BURST", "42")
	cfg := defaultRuntimeForServerTest()
	cfg.RateLimit.Profile = "strict"
	cfg.RateLimit.Locked = true
	cfg.Proxy.NetworkAllowlist = []string{"10.0.0.0/8"}
	cfg.Proxy.TrustedProxies = []string{"192.0.2.1"}

	opts := resolvedServerOptions(cfg)
	if opts.RateLimit.Profile != ratelimit.ProfileStrict || !opts.RateLimit.Locked {
		t.Fatalf("rate limit profile/lock = %q/%v", opts.RateLimit.Profile, opts.RateLimit.Locked)
	}
	if got := opts.RateLimit.Tiers[ratelimit.TierProxy].Burst; got != 42 {
		t.Fatalf("legacy proxy burst = %d, want 42", got)
	}
	if len(opts.NetworkAllowlist) != 1 || len(opts.TrustedProxies) != 1 {
		t.Fatalf("parsed network options = %#v", opts)
	}
}

func TestClearResolvedSecretEnvironment(t *testing.T) {
	for _, key := range []string{"DATABASE_URL", "AGENT_VAULT_MASTER_PASSWORD", "AGENT_VAULT_SMTP_PASSWORD"} {
		t.Setenv(key, "must-be-cleared")
	}
	cfg := defaultRuntimeForServerTest()
	cfg.SMTP.Password = mustServerConfigSecret(t, "env://CUSTOM_SMTP_SECRET", "custom")
	t.Setenv("CUSTOM_SMTP_SECRET", "must-also-be-cleared")
	if err := clearResolvedSecretEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("CUSTOM_SMTP_SECRET"); ok {
		t.Fatal("custom referenced secret remains set")
	}
	for _, key := range []string{"DATABASE_URL", "AGENT_VAULT_MASTER_PASSWORD", "AGENT_VAULT_SMTP_PASSWORD"} {
		if _, ok := os.LookupEnv(key); ok {
			t.Fatalf("%s remains set", key)
		}
	}
}

func mustServerConfigSecret(t *testing.T, raw, value string) runtimeconfig.SecretValue {
	t.Helper()
	ref, err := runtimeconfig.ParseSecretRef(raw)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := (runtimeconfig.Resolver{LookupEnv: func(string) (string, bool) { return value, true }}).Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func newServerConfigTestCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "server"}
	f := cmd.Flags()
	f.String("config", "", "")
	f.String("host", DefaultHost, "")
	f.Int("port", DefaultPort, "")
	f.Int("mitm-port", DefaultMITMPort, "")
	f.Bool("detach", false, "")
	f.String("log-level", "info", "")
	f.Int64("max-response-bytes", 0, "")
	f.Int64("max-request-bytes", 1<<30, "")
	f.String("database-url", "", "")
	return cmd
}

func defaultRuntimeForServerTest() runtimeconfig.Runtime {
	return runtimeconfig.Defaults()
}
