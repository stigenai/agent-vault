package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fullTOML = `schema_version = 1

[server]
host = "0.0.0.0"
port = 24321
proxy_port = 24322
external_address = "https://vault.toml.example"
log_level = "debug"
detach = true

[database]
url = "env://TOML_DATABASE_URL"
sqlite_path = ""
max_open_conns = 40
max_idle_conns = 20
conn_max_lifetime = "10m"

[proxy]
max_request_bytes = 2000
max_response_bytes = 1000
allow_private_ranges = true
network_allowlist = ["10.0.0.0/8"]
trusted_proxies = ["192.0.2.1"]

[client]
address = "https://client.toml.example"
vault = "toml-vault"
workload_api = "unix:///toml/spire.sock"
trust_domains = ["spiffe://toml.example"]

[encryption]
legacy_master_password = "env://TOML_MASTER_PASSWORD"

[smtp]
host = "smtp.toml.example"
port = 2465
username = "toml-user"
password = "file:///toml/smtp-password"
from = "vault@toml.example"
from_name = "TOML Vault"
tls_mode = "required"
tls_skip_verify = true

[logs]
max_age = "48h"
max_rows_per_vault = 20000
retention_locked = true

[rate_limit]
profile = "strict"
locked = true

[telemetry]
enabled = false
`

func TestDefaults(t *testing.T) {
	want := Runtime{
		SchemaVersion: SchemaVersion,
		Server:        Server{Host: "127.0.0.1", Port: 14321, ProxyPort: 14322, LogLevel: "info"},
		Database:      Database{MaxOpenConns: 25, MaxIdleConns: 10, ConnMaxLifetime: 5 * time.Minute},
		Proxy:         Proxy{MaxRequestBytes: 1 << 30},
		Client:        Client{Address: "http://127.0.0.1:14321"},
		SMTP:          SMTP{Port: 587, FromName: "Agent Vault", TLSMode: "opportunistic"},
		Logs:          Logs{MaxAge: 7 * 24 * time.Hour, MaxRowsPerVault: 10000},
		RateLimit:     RateLimit{Profile: "default"},
		Telemetry:     Telemetry{Enabled: true},
	}
	if got := Defaults(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Defaults() mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestLoadFullTOMLAndSources(t *testing.T) {
	path := writeConfig(t, "full.toml", fullTOML)
	got, err := Load(Options{
		Path: path,
		LookupEnv: mapEnv(map[string]string{
			"TOML_DATABASE_URL": "postgres://toml/db", "TOML_MASTER_PASSWORD": "toml-master-password",
		}),
		Resolver: Resolver{ReadFile: func(path string, _ int64) ([]byte, error) {
			if path != "/toml/smtp-password" {
				t.Fatalf("unexpected secret path %q", path)
			}
			return []byte("toml-smtp-password"), nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Runtime{
		SchemaVersion: 1,
		Server: Server{
			Host: "0.0.0.0", Port: 24321, ProxyPort: 24322,
			ExternalAddress: "https://vault.toml.example", LogLevel: "debug", Detach: true,
		},
		Database: Database{
			URL: secretValue("env://TOML_DATABASE_URL", "postgres://toml/db"), MaxOpenConns: 40, MaxIdleConns: 20, ConnMaxLifetime: 10 * time.Minute,
		},
		Proxy: Proxy{
			MaxRequestBytes: 2000, MaxResponseBytes: 1000, AllowPrivateRanges: true,
			NetworkAllowlist: []string{"10.0.0.0/8"}, TrustedProxies: []string{"192.0.2.1"},
		},
		Client: Client{
			Address: "https://client.toml.example", Vault: "toml-vault",
			WorkloadAPI: "unix:///toml/spire.sock", TrustDomains: []string{"spiffe://toml.example"},
		},
		Encryption: Encryption{LegacyMasterPassword: secretValue("env://TOML_MASTER_PASSWORD", "toml-master-password")},
		SMTP: SMTP{
			Host: "smtp.toml.example", Port: 2465, Username: "toml-user",
			Password: secretValue("file:///toml/smtp-password", "toml-smtp-password"),
			From:     "vault@toml.example", FromName: "TOML Vault", TLSMode: "required", TLSSkipVerify: true,
		},
		Logs:      Logs{MaxAge: 48 * time.Hour, MaxRowsPerVault: 20000, RetentionLocked: true},
		RateLimit: RateLimit{Profile: "strict", Locked: true},
		Telemetry: Telemetry{Enabled: false},
	}
	if !reflect.DeepEqual(got.Config, want) {
		t.Fatalf("loaded config mismatch\n got: %#v\nwant: %#v", got.Config, want)
	}
	if got.Path != path {
		t.Fatalf("Path = %q, want %q", got.Path, path)
	}
	if len(got.Sources) != len(fieldNames) {
		t.Fatalf("Sources has %d fields, want %d", len(got.Sources), len(fieldNames))
	}
	for _, field := range fieldNames {
		if got.Sources[field] != SourceTOML {
			t.Errorf("source %s = %q, want toml", field, got.Sources[field])
		}
	}
}

func TestLoadPrecedenceEveryField(t *testing.T) {
	path := writeConfig(t, "precedence.toml", fullTOML)
	env := map[string]string{
		"TOML_DATABASE_URL": "postgres://toml/db", "FLAG_DATABASE_URL": "postgres://flag/db",
		"TOML_MASTER_PASSWORD": "toml-master-password", "FLAG_MASTER_PASSWORD": "flag-master-password",
		"FLAG_SMTP_PASSWORD": "flag-smtp-password",
		"AGENT_VAULT_HOST":   "env-host", "PORT": "34321", "AGENT_VAULT_MITM_PORT": "34322",
		"AGENT_VAULT_ADDR": "https://env.example", "AGENT_VAULT_LOG_LEVEL": "info", "AGENT_VAULT_DETACH": "false",
		"DATABASE_URL": "postgres://env/db", "AGENT_VAULT_SQLITE_PATH": "",
		"DB_MAX_OPEN_CONNS": "50", "DB_MAX_IDLE_CONNS": "30", "DB_CONN_MAX_LIFETIME": "20m",
		"AGENT_VAULT_MAX_REQUEST_BYTES": "3000", "AGENT_VAULT_MAX_RESPONSE_BYTES": "1500",
		"AGENT_VAULT_ALLOW_PRIVATE_RANGES": "false", "AGENT_VAULT_NETWORK_ALLOWLIST": "172.16.0.0/12",
		"AGENT_VAULT_TRUSTED_PROXIES": "198.51.100.1",
		"AGENT_VAULT_VAULT":           "env-vault", "SPIFFE_ENDPOINT_SOCKET": "unix:///env/spire.sock",
		"AGENT_VAULT_SPIFFE_TRUST_DOMAINS": "spiffe://env.example",
		"AGENT_VAULT_MASTER_PASSWORD":      "env-master-password", "AGENT_VAULT_SMTP_PASSWORD": "env-smtp-password",
		"AGENT_VAULT_SMTP_HOST": "smtp.env.example", "AGENT_VAULT_SMTP_PORT": "3587",
		"AGENT_VAULT_SMTP_USERNAME": "env-user", "AGENT_VAULT_SMTP_FROM": "vault@env.example",
		"AGENT_VAULT_SMTP_FROM_NAME": "Env Vault", "AGENT_VAULT_SMTP_TLS_MODE": "none",
		"AGENT_VAULT_SMTP_TLS_SKIP_VERIFY": "false",
		"AGENT_VAULT_LOGS_MAX_AGE_HOURS":   "72", "AGENT_VAULT_LOGS_MAX_ROWS_PER_VAULT": "30000",
		"AGENT_VAULT_LOGS_RETENTION_LOCK": "false", "AGENT_VAULT_RATELIMIT_PROFILE": "loose",
		"AGENT_VAULT_RATELIMIT_LOCK": "false", "AGENT_VAULT_TELEMETRY": "true",
	}

	resolver := Resolver{ReadFile: func(string, int64) ([]byte, error) { return []byte("toml-smtp-password"), nil }}
	result, err := Load(Options{Path: path, LookupEnv: mapEnv(env), Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Server.Host != "env-host" || result.Config.Database.URL.RevealString() != "postgres://env/db" || result.Config.Client.Vault != "env-vault" {
		t.Fatalf("environment did not override TOML: %#v", result.Config)
	}
	for _, field := range fieldNames {
		want := SourceEnvironment
		if field == "schema_version" {
			want = SourceTOML
		}
		if result.Sources[field] != want {
			t.Errorf("environment source %s = %q, want %q", field, result.Sources[field], want)
		}
	}

	flags := allFlagOverrides()
	result, err = Load(Options{Path: path, LookupEnv: mapEnv(env), Resolver: resolver, Flags: flags})
	if err != nil {
		t.Fatal(err)
	}
	want := flagRuntime()
	if !reflect.DeepEqual(result.Config, want) {
		t.Fatalf("flag config mismatch\n got: %#v\nwant: %#v", result.Config, want)
	}
	for _, field := range fieldNames {
		if result.Sources[field] != SourceFlag {
			t.Errorf("flag source %s = %q, want flag", field, result.Sources[field])
		}
	}
}

func TestConfigDiscovery(t *testing.T) {
	explicit := writeConfig(t, "explicit.toml", strings.Replace(fullTOML, "port = 24321", "port = 11111", 1))
	envPath := writeConfig(t, "env.toml", strings.Replace(fullTOML, "port = 24321", "port = 22222", 1))
	defaultPath := writeConfig(t, "default.toml", strings.Replace(fullTOML, "port = 24321", "port = 33333", 1))

	tests := []struct {
		name string
		opts Options
		want int
	}{
		{"explicit beats env", Options{Path: explicit, DefaultPath: defaultPath, LookupEnv: discoveryEnv(envPath), Resolver: discoveryResolver()}, 11111},
		{"env beats default", Options{DefaultPath: defaultPath, LookupEnv: discoveryEnv(envPath), Resolver: discoveryResolver()}, 22222},
		{"default", Options{DefaultPath: defaultPath, LookupEnv: discoveryEnv(""), Resolver: discoveryResolver()}, 33333},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Load(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got.Config.Server.Port != tc.want {
				t.Fatalf("port = %d, want %d", got.Config.Server.Port, tc.want)
			}
		})
	}
}

func TestMissingFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.toml")
	if got, err := Load(Options{DefaultPath: missing, LookupEnv: emptyEnv}); err != nil {
		t.Fatalf("optional default: %v", err)
	} else if !reflect.DeepEqual(got.Config, Defaults()) {
		t.Fatalf("missing default changed defaults: %#v", got.Config)
	}
	for _, tc := range []Options{
		{Path: missing, LookupEnv: emptyEnv},
		{DefaultPath: filepath.Join(t.TempDir(), "also-missing.toml"), LookupEnv: mapEnv(map[string]string{"AGENT_VAULT_CONFIG": missing})},
	} {
		if _, err := Load(tc); err == nil || !strings.Contains(err.Error(), "no such file") {
			t.Fatalf("required missing file error = %v", err)
		}
	}
}

func TestFlyAppNameRemainsExternalAddressFallback(t *testing.T) {
	result, err := Load(Options{
		DefaultPath: filepath.Join(t.TempDir(), "missing.toml"),
		LookupEnv:   mapEnv(map[string]string{"FLY_APP_NAME": "fleet-vault"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Config.Server.ExternalAddress; got != "https://fleet-vault.fly.dev" {
		t.Fatalf("external address = %q", got)
	}
	if result.Sources["server.external_address"] != SourceEnvironment {
		t.Fatalf("source = %q", result.Sources["server.external_address"])
	}
}

func TestStrictSchemaErrors(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"missing version", "[server]\nport=14321\n", "schema_version is required"},
		{"future version", "schema_version=2\n", "unsupported version 2"},
		{"unknown top level", "schema_version=1\nunknown=true\n", "strict mode"},
		{"unknown nested", "schema_version=1\n[server]\nunknown=true\n", "strict mode"},
		{"wrong type", "schema_version=1\n[server]\nport=\"bad\"\n", "cannot decode"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, "bad.toml", tc.body)
			_, err := Load(Options{Path: path, LookupEnv: emptyEnv})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"empty host", "[server]\nhost=\"\"", "server.host"},
		{"bad api port", "[server]\nport=0", "server.port"},
		{"bad proxy port", "[server]\nproxy_port=70000", "server.proxy_port"},
		{"bad log level", "[server]\nlog_level=\"trace\"", "server.log_level"},
		{"bad external URL", "[server]\nexternal_address=\"ftp://bad\"", "server.external_address"},
		{"two databases", "[database]\nurl=\"env://TEST_DATABASE_URL\"\nsqlite_path=\"/tmp/x\"", "mutually exclusive"},
		{"negative open", "[database]\nmax_open_conns=-1", "database.max_open_conns"},
		{"idle exceeds open", "[database]\nmax_open_conns=1\nmax_idle_conns=2", "database.max_idle_conns"},
		{"zero lifetime", "[database]\nconn_max_lifetime=\"0s\"", "database.conn_max_lifetime"},
		{"zero request bytes", "[proxy]\nmax_request_bytes=0", "proxy.max_request_bytes"},
		{"negative response bytes", "[proxy]\nmax_response_bytes=-1", "proxy.max_response_bytes"},
		{"empty allowlist entry", "[proxy]\nnetwork_allowlist=[\"\"]", "proxy.network_allowlist"},
		{"bad client URL", "[client]\naddress=\"relative\"", "client.address"},
		{"bad workload socket", "[client]\nworkload_api=\"tcp://spire\"", "client.workload_api"},
		{"bad trust domain", "[client]\ntrust_domains=[\"https://example\"]", "client.trust_domains"},
		{"negative log age", "[logs]\nmax_age=\"-1h\"", "logs.max_age"},
		{"negative log rows", "[logs]\nmax_rows_per_vault=-1", "logs.max_rows_per_vault"},
		{"bad rate profile", "[rate_limit]\nprofile=\"fast\"", "rate_limit.profile"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, "invalid.toml", "schema_version=1\n"+tc.body+"\n")
			lookup := emptyEnv
			if tc.name == "two databases" {
				lookup = mapEnv(map[string]string{"TEST_DATABASE_URL": "postgres://db/x"})
			}
			_, err := Load(Options{Path: path, LookupEnv: lookup})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestInvalidEnvironmentErrorsAreDeterministic(t *testing.T) {
	tests := []struct {
		name, key, value, want string
	}{
		{"integer", "PORT", "nope", `environment PORT="nope": expected integer`},
		{"boolean", "AGENT_VAULT_TELEMETRY", "sometimes", `environment AGENT_VAULT_TELEMETRY="sometimes": expected boolean`},
		{"duration", "DB_CONN_MAX_LIFETIME", "soon", `environment DB_CONN_MAX_LIFETIME="soon": expected duration`},
		{"hours", "AGENT_VAULT_LOGS_MAX_AGE_HOURS", "later", `environment AGENT_VAULT_LOGS_MAX_AGE_HOURS="later": expected number of hours`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(Options{DefaultPath: filepath.Join(t.TempDir(), "none"), LookupEnv: mapEnv(map[string]string{tc.key: tc.value})})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
		})
	}
}

func allFlagOverrides() Partial {
	version, host, port, proxyPort := 1, "flag-host", 44321, 44322
	external, level, detach := "https://flag.example", "debug", true
	dbURL, sqlitePath, open, idle := mustSecretRef("env://FLAG_DATABASE_URL"), "", 60, 40
	masterPassword := mustSecretRef("env://FLAG_MASTER_PASSWORD")
	smtpPassword := mustSecretRef("env://FLAG_SMTP_PASSWORD")
	smtpHost, smtpPort, smtpUsername := "smtp.flag.example", 4465, "flag-user"
	smtpFrom, smtpFromName, smtpTLSMode, smtpSkipVerify := "vault@flag.example", "Flag Vault", "required", true
	lifetime := Duration(30 * time.Minute)
	requestBytes, responseBytes, private := int64(4000), int64(2500), true
	allowlist, proxies := []string{"10.10.0.0/16"}, []string{"203.0.113.1"}
	address, vault, socket := "https://flag-client.example", "flag-vault", "unix:///flag/spire.sock"
	trustDomains := []string{"spiffe://flag.example"}
	maxAge, rows, retention := Duration(96*time.Hour), int64(40000), true
	profile, locked, telemetry := "off", true, false
	return Partial{
		SchemaVersion: &version,
		Server:        PartialServer{Host: &host, Port: &port, ProxyPort: &proxyPort, ExternalAddress: &external, LogLevel: &level, Detach: &detach},
		Database:      PartialDatabase{URL: &dbURL, SQLitePath: &sqlitePath, MaxOpenConns: &open, MaxIdleConns: &idle, ConnMaxLifetime: &lifetime},
		Proxy:         PartialProxy{MaxRequestBytes: &requestBytes, MaxResponseBytes: &responseBytes, AllowPrivateRanges: &private, NetworkAllowlist: &allowlist, TrustedProxies: &proxies},
		Client:        PartialClient{Address: &address, Vault: &vault, WorkloadAPI: &socket, TrustDomains: &trustDomains},
		Encryption:    PartialEncryption{LegacyMasterPassword: &masterPassword},
		SMTP: PartialSMTP{
			Host: &smtpHost, Port: &smtpPort, Username: &smtpUsername, Password: &smtpPassword,
			From: &smtpFrom, FromName: &smtpFromName, TLSMode: &smtpTLSMode, TLSSkipVerify: &smtpSkipVerify,
		},
		Logs:      PartialLogs{MaxAge: &maxAge, MaxRowsPerVault: &rows, RetentionLocked: &retention},
		RateLimit: PartialRateLimit{Profile: &profile, Locked: &locked},
		Telemetry: PartialTelemetry{Enabled: &telemetry},
	}
}

func flagRuntime() Runtime {
	return Runtime{
		SchemaVersion: 1,
		Server:        Server{Host: "flag-host", Port: 44321, ProxyPort: 44322, ExternalAddress: "https://flag.example", LogLevel: "debug", Detach: true},
		Database:      Database{URL: secretValue("env://FLAG_DATABASE_URL", "postgres://flag/db"), MaxOpenConns: 60, MaxIdleConns: 40, ConnMaxLifetime: 30 * time.Minute},
		Proxy:         Proxy{MaxRequestBytes: 4000, MaxResponseBytes: 2500, AllowPrivateRanges: true, NetworkAllowlist: []string{"10.10.0.0/16"}, TrustedProxies: []string{"203.0.113.1"}},
		Client:        Client{Address: "https://flag-client.example", Vault: "flag-vault", WorkloadAPI: "unix:///flag/spire.sock", TrustDomains: []string{"spiffe://flag.example"}},
		Encryption:    Encryption{LegacyMasterPassword: secretValue("env://FLAG_MASTER_PASSWORD", "flag-master-password")},
		SMTP: SMTP{
			Host: "smtp.flag.example", Port: 4465, Username: "flag-user",
			Password: secretValue("env://FLAG_SMTP_PASSWORD", "flag-smtp-password"),
			From:     "vault@flag.example", FromName: "Flag Vault", TLSMode: "required", TLSSkipVerify: true,
		},
		Logs:      Logs{MaxAge: 96 * time.Hour, MaxRowsPerVault: 40000, RetentionLocked: true},
		RateLimit: RateLimit{Profile: "off", Locked: true},
		Telemetry: Telemetry{Enabled: false},
	}
}

func discoveryEnv(configPath string) LookupEnv {
	values := map[string]string{
		"TOML_DATABASE_URL":    "postgres://toml/db",
		"TOML_MASTER_PASSWORD": "toml-master-password",
	}
	if configPath != "" {
		values["AGENT_VAULT_CONFIG"] = configPath
	}
	return mapEnv(values)
}

func discoveryResolver() Resolver {
	return Resolver{ReadFile: func(path string, _ int64) ([]byte, error) {
		if path != "/toml/smtp-password" {
			return nil, fmt.Errorf("unexpected secret path %q", path)
		}
		return []byte("toml-smtp-password"), nil
	}}
}

func writeConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func emptyEnv(string) (string, bool) { return "", false }

func mapEnv(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func mustSecretRef(raw string) SecretRef {
	ref, err := ParseSecretRef(raw)
	if err != nil {
		panic(err)
	}
	return ref
}

func secretValue(ref, value string) SecretValue {
	return newSecretValue(mustSecretRef(ref), []byte(value))
}
