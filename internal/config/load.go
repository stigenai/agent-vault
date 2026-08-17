package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type LookupEnv func(string) (string, bool)

// Options controls runtime configuration discovery and the highest-precedence
// flag layer. DefaultPath exists so tests and non-Linux packaging can replace
// /etc/agent-vault/server.toml without changing discovery semantics.
type Options struct {
	Path        string
	DefaultPath string
	LookupEnv   LookupEnv
	Flags       Partial
}

// Load resolves defaults < TOML < environment < flags and validates the
// result. A missing default file is ignored; a missing explicitly selected or
// AGENT_VAULT_CONFIG file is an error.
func Load(opts Options) (Result, error) {
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	result := Result{Config: Defaults(), Sources: defaultSources()}

	path, required := discoverPath(opts, lookup)
	if path != "" {
		partial, err := decodeFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && !required {
				// The system-wide default is optional.
			} else {
				return Result{}, fmt.Errorf("config %q: %w", path, err)
			}
		} else {
			if partial.SchemaVersion == nil {
				return Result{}, fmt.Errorf("config %q: schema_version is required", path)
			}
			applyPartial(&result, partial, SourceTOML)
			result.Path = path
		}
	}

	if err := applyEnvironment(&result, lookup); err != nil {
		return Result{}, err
	}
	applyPartial(&result, opts.Flags, SourceFlag)
	if err := result.Config.Validate(); err != nil {
		return Result{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return result, nil
}

func discoverPath(opts Options, lookup LookupEnv) (path string, required bool) {
	if opts.Path != "" {
		return opts.Path, true
	}
	if path, ok := lookup("AGENT_VAULT_CONFIG"); ok && strings.TrimSpace(path) != "" {
		return path, true
	}
	path = opts.DefaultPath
	if path == "" {
		path = DefaultPath
	}
	return path, false
}

func decodeFile(path string) (Partial, error) {
	f, err := os.Open(path)
	if err != nil {
		return Partial{}, err
	}
	defer func() { _ = f.Close() }()
	return decode(f)
}

func decode(r io.Reader) (Partial, error) {
	var partial Partial
	dec := toml.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&partial); err != nil {
		return Partial{}, err
	}
	return partial, nil
}

func applyEnvironment(result *Result, lookup LookupEnv) error {
	setString := func(env, field string, target *string) {
		if value, ok := lookup(env); ok {
			*target = value
			result.Sources[field] = SourceEnvironment
		}
	}
	setInt := func(env, field string, target *int) error {
		value, ok := lookup(env)
		if !ok {
			return nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return envError(env, value, "integer")
		}
		*target = parsed
		result.Sources[field] = SourceEnvironment
		return nil
	}
	setInt64 := func(env, field string, target *int64) error {
		value, ok := lookup(env)
		if !ok {
			return nil
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return envError(env, value, "integer")
		}
		*target = parsed
		result.Sources[field] = SourceEnvironment
		return nil
	}
	setBool := func(env, field string, target *bool) error {
		value, ok := lookup(env)
		if !ok {
			return nil
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return envError(env, value, "boolean")
		}
		*target = parsed
		result.Sources[field] = SourceEnvironment
		return nil
	}
	setDuration := func(env, field string, target *time.Duration) error {
		value, ok := lookup(env)
		if !ok {
			return nil
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return envError(env, value, "duration")
		}
		*target = parsed
		result.Sources[field] = SourceEnvironment
		return nil
	}
	setList := func(env, field string, target *[]string) {
		value, ok := lookup(env)
		if !ok {
			return
		}
		*target = splitList(value)
		result.Sources[field] = SourceEnvironment
	}

	setString("AGENT_VAULT_HOST", "server.host", &result.Config.Server.Host)
	if err := setInt("PORT", "server.port", &result.Config.Server.Port); err != nil {
		return err
	}
	if err := setInt("AGENT_VAULT_MITM_PORT", "server.proxy_port", &result.Config.Server.ProxyPort); err != nil {
		return err
	}
	setString("AGENT_VAULT_ADDR", "server.external_address", &result.Config.Server.ExternalAddress)
	setString("AGENT_VAULT_LOG_LEVEL", "server.log_level", &result.Config.Server.LogLevel)
	if err := setBool("AGENT_VAULT_DETACH", "server.detach", &result.Config.Server.Detach); err != nil {
		return err
	}

	setString("DATABASE_URL", "database.url", &result.Config.Database.URL)
	setString("AGENT_VAULT_SQLITE_PATH", "database.sqlite_path", &result.Config.Database.SQLitePath)
	if err := setInt("DB_MAX_OPEN_CONNS", "database.max_open_conns", &result.Config.Database.MaxOpenConns); err != nil {
		return err
	}
	if err := setInt("DB_MAX_IDLE_CONNS", "database.max_idle_conns", &result.Config.Database.MaxIdleConns); err != nil {
		return err
	}
	if err := setDuration("DB_CONN_MAX_LIFETIME", "database.conn_max_lifetime", &result.Config.Database.ConnMaxLifetime); err != nil {
		return err
	}

	if err := setInt64("AGENT_VAULT_MAX_REQUEST_BYTES", "proxy.max_request_bytes", &result.Config.Proxy.MaxRequestBytes); err != nil {
		return err
	}
	if err := setInt64("AGENT_VAULT_MAX_RESPONSE_BYTES", "proxy.max_response_bytes", &result.Config.Proxy.MaxResponseBytes); err != nil {
		return err
	}
	if err := setBool("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "proxy.allow_private_ranges", &result.Config.Proxy.AllowPrivateRanges); err != nil {
		return err
	}
	setList("AGENT_VAULT_NETWORK_ALLOWLIST", "proxy.network_allowlist", &result.Config.Proxy.NetworkAllowlist)
	setList("AGENT_VAULT_TRUSTED_PROXIES", "proxy.trusted_proxies", &result.Config.Proxy.TrustedProxies)

	setString("AGENT_VAULT_ADDR", "client.address", &result.Config.Client.Address)
	setString("AGENT_VAULT_VAULT", "client.vault", &result.Config.Client.Vault)
	setString("SPIFFE_ENDPOINT_SOCKET", "client.workload_api", &result.Config.Client.WorkloadAPI)
	setList("AGENT_VAULT_SPIFFE_TRUST_DOMAINS", "client.trust_domains", &result.Config.Client.TrustDomains)

	if value, ok := lookup("AGENT_VAULT_LOGS_MAX_AGE_HOURS"); ok {
		hours, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return envError("AGENT_VAULT_LOGS_MAX_AGE_HOURS", value, "number of hours")
		}
		result.Config.Logs.MaxAge = time.Duration(hours * float64(time.Hour))
		result.Sources["logs.max_age"] = SourceEnvironment
	}
	if err := setInt64("AGENT_VAULT_LOGS_MAX_ROWS_PER_VAULT", "logs.max_rows_per_vault", &result.Config.Logs.MaxRowsPerVault); err != nil {
		return err
	}
	if err := setBool("AGENT_VAULT_LOGS_RETENTION_LOCK", "logs.retention_locked", &result.Config.Logs.RetentionLocked); err != nil {
		return err
	}

	setString("AGENT_VAULT_RATELIMIT_PROFILE", "rate_limit.profile", &result.Config.RateLimit.Profile)
	if err := setBool("AGENT_VAULT_RATELIMIT_LOCK", "rate_limit.locked", &result.Config.RateLimit.Locked); err != nil {
		return err
	}
	if err := setBool("AGENT_VAULT_TELEMETRY", "telemetry.enabled", &result.Config.Telemetry.Enabled); err != nil {
		return err
	}
	return nil
}

func envError(name, value, want string) error {
	return fmt.Errorf("environment %s=%q: expected %s", name, value, want)
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, strings.TrimSpace(part))
	}
	return result
}

func applyPartial(result *Result, partial Partial, source Source) {
	set := func(field string) { result.Sources[field] = source }
	if partial.SchemaVersion != nil {
		result.Config.SchemaVersion = *partial.SchemaVersion
		set("schema_version")
	}
	if v := partial.Server.Host; v != nil {
		result.Config.Server.Host = *v
		set("server.host")
	}
	if v := partial.Server.Port; v != nil {
		result.Config.Server.Port = *v
		set("server.port")
	}
	if v := partial.Server.ProxyPort; v != nil {
		result.Config.Server.ProxyPort = *v
		set("server.proxy_port")
	}
	if v := partial.Server.ExternalAddress; v != nil {
		result.Config.Server.ExternalAddress = *v
		set("server.external_address")
	}
	if v := partial.Server.LogLevel; v != nil {
		result.Config.Server.LogLevel = strings.ToLower(*v)
		set("server.log_level")
	}
	if v := partial.Server.Detach; v != nil {
		result.Config.Server.Detach = *v
		set("server.detach")
	}
	if v := partial.Database.URL; v != nil {
		result.Config.Database.URL = *v
		set("database.url")
	}
	if v := partial.Database.SQLitePath; v != nil {
		result.Config.Database.SQLitePath = *v
		set("database.sqlite_path")
	}
	if v := partial.Database.MaxOpenConns; v != nil {
		result.Config.Database.MaxOpenConns = *v
		set("database.max_open_conns")
	}
	if v := partial.Database.MaxIdleConns; v != nil {
		result.Config.Database.MaxIdleConns = *v
		set("database.max_idle_conns")
	}
	if v := partial.Database.ConnMaxLifetime; v != nil {
		result.Config.Database.ConnMaxLifetime = time.Duration(*v)
		set("database.conn_max_lifetime")
	}
	if v := partial.Proxy.MaxRequestBytes; v != nil {
		result.Config.Proxy.MaxRequestBytes = *v
		set("proxy.max_request_bytes")
	}
	if v := partial.Proxy.MaxResponseBytes; v != nil {
		result.Config.Proxy.MaxResponseBytes = *v
		set("proxy.max_response_bytes")
	}
	if v := partial.Proxy.AllowPrivateRanges; v != nil {
		result.Config.Proxy.AllowPrivateRanges = *v
		set("proxy.allow_private_ranges")
	}
	if v := partial.Proxy.NetworkAllowlist; v != nil {
		result.Config.Proxy.NetworkAllowlist = append([]string(nil), (*v)...)
		set("proxy.network_allowlist")
	}
	if v := partial.Proxy.TrustedProxies; v != nil {
		result.Config.Proxy.TrustedProxies = append([]string(nil), (*v)...)
		set("proxy.trusted_proxies")
	}
	if v := partial.Client.Address; v != nil {
		result.Config.Client.Address = *v
		set("client.address")
	}
	if v := partial.Client.Vault; v != nil {
		result.Config.Client.Vault = *v
		set("client.vault")
	}
	if v := partial.Client.WorkloadAPI; v != nil {
		result.Config.Client.WorkloadAPI = *v
		set("client.workload_api")
	}
	if v := partial.Client.TrustDomains; v != nil {
		result.Config.Client.TrustDomains = append([]string(nil), (*v)...)
		set("client.trust_domains")
	}
	if v := partial.Logs.MaxAge; v != nil {
		result.Config.Logs.MaxAge = time.Duration(*v)
		set("logs.max_age")
	}
	if v := partial.Logs.MaxRowsPerVault; v != nil {
		result.Config.Logs.MaxRowsPerVault = *v
		set("logs.max_rows_per_vault")
	}
	if v := partial.Logs.RetentionLocked; v != nil {
		result.Config.Logs.RetentionLocked = *v
		set("logs.retention_locked")
	}
	if v := partial.RateLimit.Profile; v != nil {
		result.Config.RateLimit.Profile = strings.ToLower(*v)
		set("rate_limit.profile")
	}
	if v := partial.RateLimit.Locked; v != nil {
		result.Config.RateLimit.Locked = *v
		set("rate_limit.locked")
	}
	if v := partial.Telemetry.Enabled; v != nil {
		result.Config.Telemetry.Enabled = *v
		set("telemetry.enabled")
	}
}
