package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func openPostgres(cfg StoreConfig) (*SQLStore, error) {
	maxOpen := cfg.MaxOpenConns
	if !cfg.PoolConfigured {
		maxOpen = envInt("DB_MAX_OPEN_CONNS", 25)
	}
	maxIdle := cfg.MaxIdleConns
	if !cfg.PoolConfigured {
		maxIdle = envInt("DB_MAX_IDLE_CONNS", 10)
	}
	lifetime := cfg.ConnMaxLifetime
	if !cfg.PoolConfigured {
		lifetime = envDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute)
	}
	connectTimeout := cfg.ConnectTimeout
	if !cfg.PoolConfigured {
		connectTimeout = envDuration("DB_CONNECT_TIMEOUT", 10*time.Second)
	}
	tlsMode := cfg.TLSMode
	tlsRootCert := cfg.TLSRootCert
	if !cfg.PoolConfigured {
		tlsMode = strings.ToLower(os.Getenv("DB_TLS_MODE"))
		tlsRootCert = os.Getenv("DB_TLS_ROOT_CERT")
	}
	if err := validatePostgresRuntime(maxOpen, maxIdle, lifetime, connectTimeout, tlsMode, tlsRootCert); err != nil {
		return nil, err
	}
	databaseURL, err := configurePostgresURL(cfg.DatabaseURL, tlsMode, tlsRootCert, connectTimeout)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %s", sanitizePostgresDiagnostic(err, cfg.DatabaseURL))
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging postgres: %s", sanitizePostgresDiagnostic(err, cfg.DatabaseURL))
	}

	if err := runGORMMigrations(db, "postgres"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %s", sanitizePostgresDiagnostic(err, cfg.DatabaseURL))
	}

	return &SQLStore{db: db, dialect: PostgresDialect{}}, nil
}

func validatePostgresRuntime(maxOpen, maxIdle int, lifetime, connectTimeout time.Duration, tlsMode, tlsRootCert string) error {
	if maxOpen < 1 || maxOpen > 1000 {
		return fmt.Errorf("postgres max open connections must be between 1 and 1000")
	}
	if maxIdle < 0 || maxIdle > maxOpen {
		return fmt.Errorf("postgres max idle connections must be between 0 and max open connections")
	}
	if lifetime < 30*time.Second || lifetime > 24*time.Hour {
		return fmt.Errorf("postgres connection lifetime must be between 30s and 24h")
	}
	if connectTimeout < time.Second || connectTimeout > time.Minute {
		return fmt.Errorf("postgres connect timeout must be between 1s and 1m")
	}
	switch tlsMode {
	case "", "disable", "require":
		if tlsRootCert != "" {
			return fmt.Errorf("postgres TLS root certificate requires verify-ca or verify-full")
		}
	case "verify-ca", "verify-full":
		if !filepath.IsAbs(tlsRootCert) {
			return fmt.Errorf("postgres TLS root certificate must be an absolute path")
		}
	default:
		return fmt.Errorf("postgres TLS mode must be disable, require, verify-ca, or verify-full")
	}
	return nil
}

func configurePostgresURL(rawURL, tlsMode, tlsRootCert string, connectTimeout time.Duration) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("postgres connection configuration is invalid")
	}
	query := parsed.Query()
	if tlsMode != "" {
		if existing := query.Get("sslmode"); existing != "" && existing != tlsMode {
			return "", fmt.Errorf("postgres TLS mode conflicts with connection URL")
		}
		query.Set("sslmode", tlsMode)
	}
	if tlsRootCert != "" {
		if existing := query.Get("sslrootcert"); existing != "" && existing != tlsRootCert {
			return "", fmt.Errorf("postgres TLS root certificate conflicts with connection URL")
		}
		query.Set("sslrootcert", tlsRootCert)
	}
	seconds := int((connectTimeout + time.Second - 1) / time.Second)
	query.Set("connect_timeout", strconv.Itoa(seconds))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

var postgresURLCredentials = regexp.MustCompile(`(?i)(postgres(?:ql)?://[^:/@[:space:]]+:)[^@[:space:]]+@`)

func sanitizePostgresDiagnostic(err error, rawURL string) string {
	if err == nil {
		return ""
	}
	message := strings.ReplaceAll(err.Error(), rawURL, RedactURL(rawURL))
	if parsed, parseErr := url.Parse(rawURL); parseErr == nil && parsed.User != nil {
		if password, ok := parsed.User.Password(); ok && password != "" {
			for _, candidate := range []string{password, url.QueryEscape(password), url.PathEscape(password)} {
				message = strings.ReplaceAll(message, candidate, "***")
			}
		}
	}
	if parsed, parseErr := url.Parse(rawURL); parseErr == nil {
		for key, values := range parsed.Query() {
			if !strings.EqualFold(key, "password") {
				continue
			}
			for _, password := range values {
				for _, candidate := range []string{password, url.QueryEscape(password), url.PathEscape(password)} {
					message = strings.ReplaceAll(message, candidate, "***")
				}
			}
		}
	}
	return postgresURLCredentials.ReplaceAllString(message, `${1}***@`)
}
