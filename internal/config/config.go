// Package config loads and validates Agent Vault runtime configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	// SchemaVersion is the only runtime TOML schema understood by this binary.
	SchemaVersion = 1
	// DefaultPath is consulted when neither --config nor AGENT_VAULT_CONFIG is set.
	DefaultPath = "/etc/agent-vault/server.toml"
)

// Source identifies the winning configuration layer for a field.
type Source string

const (
	SourceDefault     Source = "default"
	SourceTOML        Source = "toml"
	SourceEnvironment Source = "environment"
	SourceFlag        Source = "flag"
)

// Duration is a TOML-friendly time.Duration.
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

// Runtime is the fully resolved, validated runtime configuration.
type Runtime struct {
	SchemaVersion int
	Server        Server
	Database      Database
	Proxy         Proxy
	Auth          Auth
	Client        Client
	Encryption    Encryption
	SMTP          SMTP
	Logs          Logs
	RateLimit     RateLimit
	Telemetry     Telemetry
}

type Server struct {
	Host            string
	Port            int
	ProxyPort       int
	ExternalAddress string
	LogLevel        string
	Detach          bool
}

type Database struct {
	URL             SecretValue
	SQLitePath      string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type Proxy struct {
	MaxRequestBytes    int64
	MaxResponseBytes   int64
	AllowPrivateRanges bool
	NetworkAllowlist   []string
	TrustedProxies     []string
}

// Auth controls control-plane and proxy ingress authentication.
type Auth struct {
	Mode              string
	WorkloadAPI       string
	TrustDomains      []string
	BootstrapOwnerIDs []string
}

type Client struct {
	Address      string
	Vault        string
	WorkloadAPI  string
	TrustDomains []string
}

type Relay struct {
	ListenAddress string
	RemoteAddress string
}

// Encryption contains compatibility key material until provider-backed DEK
// wrapping replaces the legacy master password.
type Encryption struct {
	LegacyMasterPassword SecretValue
}

type SMTP struct {
	Host          string
	Port          int
	Username      string
	Password      SecretValue
	From          string
	FromName      string
	TLSMode       string
	TLSSkipVerify bool
}

type Logs struct {
	MaxAge          time.Duration
	MaxRowsPerVault int64
	RetentionLocked bool
}

type RateLimit struct {
	Profile string
	Locked  bool
}

type Telemetry struct {
	Enabled bool
}

// Partial represents values supplied by one configuration layer. Pointers
// distinguish an explicit zero value from an omitted value.
type Partial struct {
	SchemaVersion *int              `toml:"schema_version"`
	Server        PartialServer     `toml:"server"`
	Database      PartialDatabase   `toml:"database"`
	Proxy         PartialProxy      `toml:"proxy"`
	Auth          PartialAuth       `toml:"auth"`
	Client        PartialClient     `toml:"client"`
	Relay         PartialRelay      `toml:"relay"`
	Encryption    PartialEncryption `toml:"encryption"`
	SMTP          PartialSMTP       `toml:"smtp"`
	Logs          PartialLogs       `toml:"logs"`
	RateLimit     PartialRateLimit  `toml:"rate_limit"`
	Telemetry     PartialTelemetry  `toml:"telemetry"`
}

type PartialServer struct {
	Host            *string `toml:"host"`
	Port            *int    `toml:"port"`
	ProxyPort       *int    `toml:"proxy_port"`
	ExternalAddress *string `toml:"external_address"`
	LogLevel        *string `toml:"log_level"`
	Detach          *bool   `toml:"detach"`
}

type PartialDatabase struct {
	URL             *SecretRef `toml:"url"`
	SQLitePath      *string    `toml:"sqlite_path"`
	MaxOpenConns    *int       `toml:"max_open_conns"`
	MaxIdleConns    *int       `toml:"max_idle_conns"`
	ConnMaxLifetime *Duration  `toml:"conn_max_lifetime"`
}

type PartialProxy struct {
	MaxRequestBytes    *int64    `toml:"max_request_bytes"`
	MaxResponseBytes   *int64    `toml:"max_response_bytes"`
	AllowPrivateRanges *bool     `toml:"allow_private_ranges"`
	NetworkAllowlist   *[]string `toml:"network_allowlist"`
	TrustedProxies     *[]string `toml:"trusted_proxies"`
}

type PartialAuth struct {
	Mode              *string   `toml:"mode"`
	WorkloadAPI       *string   `toml:"workload_api"`
	TrustDomains      *[]string `toml:"trust_domains"`
	BootstrapOwnerIDs *[]string `toml:"bootstrap_owner_ids"`
}

type PartialClient struct {
	Address      *string   `toml:"address"`
	Vault        *string   `toml:"vault"`
	WorkloadAPI  *string   `toml:"workload_api"`
	TrustDomains *[]string `toml:"trust_domains"`
}

type PartialRelay struct {
	ListenAddress *string `toml:"listen_address"`
	RemoteAddress *string `toml:"remote_address"`
}

type PartialEncryption struct {
	LegacyMasterPassword *SecretRef `toml:"legacy_master_password"`
}

type PartialSMTP struct {
	Host          *string    `toml:"host"`
	Port          *int       `toml:"port"`
	Username      *string    `toml:"username"`
	Password      *SecretRef `toml:"password"`
	From          *string    `toml:"from"`
	FromName      *string    `toml:"from_name"`
	TLSMode       *string    `toml:"tls_mode"`
	TLSSkipVerify *bool      `toml:"tls_skip_verify"`
}

type PartialLogs struct {
	MaxAge          *Duration `toml:"max_age"`
	MaxRowsPerVault *int64    `toml:"max_rows_per_vault"`
	RetentionLocked *bool     `toml:"retention_locked"`
}

type PartialRateLimit struct {
	Profile *string `toml:"profile"`
	Locked  *bool   `toml:"locked"`
}

type PartialTelemetry struct {
	Enabled *bool `toml:"enabled"`
}

// Result includes the effective configuration and source of every field.
type Result struct {
	Config  Runtime
	Sources map[string]Source
	Path    string
}

// Defaults returns the built-in configuration without consulting the process
// environment or filesystem.
func Defaults() Runtime {
	return Runtime{
		SchemaVersion: SchemaVersion,
		Server: Server{
			Host:      "127.0.0.1",
			Port:      14321,
			ProxyPort: 14322,
			LogLevel:  "info",
		},
		Database: Database{
			MaxOpenConns:    25,
			MaxIdleConns:    10,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Proxy: Proxy{
			MaxRequestBytes: 1 << 30,
		},
		Auth: Auth{Mode: "legacy"},
		Client: Client{
			Address: "http://127.0.0.1:14321",
		},
		SMTP: SMTP{
			Port:     587,
			FromName: "Agent Vault",
			TLSMode:  "opportunistic",
		},
		Logs: Logs{
			MaxAge:          7 * 24 * time.Hour,
			MaxRowsPerVault: 10000,
		},
		RateLimit: RateLimit{Profile: "default"},
		Telemetry: Telemetry{Enabled: true},
	}
}

var fieldNames = []string{
	"schema_version",
	"server.host", "server.port", "server.proxy_port", "server.external_address", "server.log_level", "server.detach",
	"database.url", "database.sqlite_path", "database.max_open_conns", "database.max_idle_conns", "database.conn_max_lifetime",
	"proxy.max_request_bytes", "proxy.max_response_bytes", "proxy.allow_private_ranges", "proxy.network_allowlist", "proxy.trusted_proxies",
	"auth.mode", "auth.workload_api", "auth.trust_domains", "auth.bootstrap_owner_ids",
	"client.address", "client.vault", "client.workload_api", "client.trust_domains",
	"encryption.legacy_master_password",
	"smtp.host", "smtp.port", "smtp.username", "smtp.password", "smtp.from", "smtp.from_name", "smtp.tls_mode", "smtp.tls_skip_verify",
	"logs.max_age", "logs.max_rows_per_vault", "logs.retention_locked",
	"rate_limit.profile", "rate_limit.locked",
	"telemetry.enabled",
}

func defaultSources() map[string]Source {
	sources := make(map[string]Source, len(fieldNames))
	for _, name := range fieldNames {
		sources[name] = SourceDefault
	}
	return sources
}

// Validate rejects configurations that cannot start safely or whose meaning is
// ambiguous. Errors name the stable TOML field path.
func (c Runtime) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version: unsupported version %d (supported: %d)", c.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(c.Server.Host) == "" {
		return fmt.Errorf("server.host: must not be empty")
	}
	if err := validPort("server.port", c.Server.Port, false); err != nil {
		return err
	}
	if err := validPort("server.proxy_port", c.Server.ProxyPort, true); err != nil {
		return err
	}
	if c.Server.LogLevel != "info" && c.Server.LogLevel != "debug" {
		return fmt.Errorf("server.log_level: invalid log level %q (accepted: info, debug)", c.Server.LogLevel)
	}
	if err := validHTTPURL("server.external_address", c.Server.ExternalAddress, true); err != nil {
		return err
	}
	if c.Database.URL.IsSet() && c.Database.SQLitePath != "" {
		return fmt.Errorf("database: url and sqlite_path are mutually exclusive")
	}
	if c.Database.MaxOpenConns < 0 {
		return fmt.Errorf("database.max_open_conns: must be at least 0")
	}
	if c.Database.MaxIdleConns < 0 {
		return fmt.Errorf("database.max_idle_conns: must be at least 0")
	}
	if c.Database.MaxOpenConns > 0 && c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("database.max_idle_conns: must not exceed max_open_conns")
	}
	if c.Database.ConnMaxLifetime <= 0 {
		return fmt.Errorf("database.conn_max_lifetime: must be greater than 0")
	}
	if c.Proxy.MaxRequestBytes <= 0 {
		return fmt.Errorf("proxy.max_request_bytes: must be greater than 0")
	}
	if c.Proxy.MaxResponseBytes < 0 {
		return fmt.Errorf("proxy.max_response_bytes: must be at least 0")
	}
	if err := validNetworkList("proxy.network_allowlist", c.Proxy.NetworkAllowlist); err != nil {
		return err
	}
	if err := validNetworkList("proxy.trusted_proxies", c.Proxy.TrustedProxies); err != nil {
		return err
	}
	if err := validateAuth(c.Auth); err != nil {
		return err
	}
	if c.Auth.Mode != "legacy" && !strings.HasPrefix(strings.ToLower(c.Server.ExternalAddress), "https://") {
		return fmt.Errorf("server.external_address: HTTPS URL is required for SPIFFE authentication")
	}
	if err := validHTTPURL("client.address", c.Client.Address, false); err != nil {
		return err
	}
	if c.Client.WorkloadAPI != "" && !strings.HasPrefix(c.Client.WorkloadAPI, "unix://") {
		return fmt.Errorf("client.workload_api: must use unix://")
	}
	for _, trustDomain := range c.Client.TrustDomains {
		if !strings.HasPrefix(trustDomain, "spiffe://") {
			return fmt.Errorf("client.trust_domains: %q must use spiffe://", trustDomain)
		}
	}
	if err := validPort("smtp.port", c.SMTP.Port, false); err != nil {
		return err
	}
	switch c.SMTP.TLSMode {
	case "opportunistic", "required", "none":
	default:
		return fmt.Errorf("smtp.tls_mode: must be opportunistic, required, or none")
	}
	if c.Logs.MaxAge < 0 {
		return fmt.Errorf("logs.max_age: must be at least 0")
	}
	if c.Logs.MaxRowsPerVault < 0 {
		return fmt.Errorf("logs.max_rows_per_vault: must be at least 0")
	}
	switch c.RateLimit.Profile {
	case "default", "strict", "loose", "off":
	default:
		return fmt.Errorf("rate_limit.profile: must be default, strict, loose, or off")
	}
	return nil
}

func validateAuth(auth Auth) error {
	switch auth.Mode {
	case "legacy":
		if auth.WorkloadAPI != "" || len(auth.TrustDomains) > 0 || len(auth.BootstrapOwnerIDs) > 0 {
			return fmt.Errorf("auth: SPIFFE settings require mode hybrid or spiffe")
		}
		return nil
	case "hybrid", "spiffe":
	default:
		return fmt.Errorf("auth.mode: must be legacy, hybrid, or spiffe")
	}
	if !strings.HasPrefix(auth.WorkloadAPI, "unix:///") {
		return fmt.Errorf("auth.workload_api: must be an absolute unix:// socket")
	}
	if len(auth.TrustDomains) == 0 {
		return fmt.Errorf("auth.trust_domains: at least one trust domain is required")
	}
	allowed := make(map[spiffeid.TrustDomain]struct{}, len(auth.TrustDomains))
	for _, raw := range auth.TrustDomains {
		domain, err := parseTrustDomain(raw)
		if err != nil {
			return fmt.Errorf("auth.trust_domains: %q: %w", raw, err)
		}
		if _, exists := allowed[domain]; exists {
			return fmt.Errorf("auth.trust_domains: duplicate %q", raw)
		}
		allowed[domain] = struct{}{}
	}
	if auth.Mode == "hybrid" && len(auth.BootstrapOwnerIDs) > 0 {
		return fmt.Errorf("auth.bootstrap_owner_ids: only valid in spiffe mode")
	}
	if auth.Mode == "spiffe" && len(auth.BootstrapOwnerIDs) == 0 {
		return fmt.Errorf("auth.bootstrap_owner_ids: at least one exact SPIFFE ID is required")
	}
	seen := make(map[spiffeid.ID]struct{}, len(auth.BootstrapOwnerIDs))
	for _, raw := range auth.BootstrapOwnerIDs {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return fmt.Errorf("auth.bootstrap_owner_ids: %q: %w", raw, err)
		}
		if id.String() != raw {
			return fmt.Errorf("auth.bootstrap_owner_ids: %q must be canonical", raw)
		}
		if _, ok := allowed[id.TrustDomain()]; !ok {
			return fmt.Errorf("auth.bootstrap_owner_ids: %q is outside configured trust domains", raw)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("auth.bootstrap_owner_ids: duplicate %q", raw)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func parseTrustDomain(raw string) (spiffeid.TrustDomain, error) {
	if !strings.HasPrefix(raw, "spiffe://") {
		return spiffeid.TrustDomain{}, fmt.Errorf("must use spiffe://")
	}
	value := strings.TrimPrefix(raw, "spiffe://")
	if value == "" || strings.ContainsAny(value, "/?#") {
		return spiffeid.TrustDomain{}, fmt.Errorf("must identify a trust domain without a path")
	}
	domain, err := spiffeid.TrustDomainFromString(value)
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	if "spiffe://"+domain.String() != raw {
		return spiffeid.TrustDomain{}, fmt.Errorf("must be canonical")
	}
	return domain, nil
}

func validPort(name string, port int, allowZero bool) error {
	if allowZero && port == 0 {
		return nil
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s: must be between 1 and 65535", name)
	}
	return nil
}

func validHTTPURL(name, raw string, optional bool) error {
	if raw == "" && optional {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s: must be an absolute http or https URL", name)
	}
	return nil
}

func validList(name string, values []string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s: entries must not be empty", name)
		}
	}
	return nil
}

func validNetworkList(name string, values []string) error {
	if err := validList(name, values); err != nil {
		return err
	}
	for _, value := range values {
		if net.ParseIP(value) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("%s: %q must be an IP address or CIDR", name, value)
		}
	}
	return nil
}
