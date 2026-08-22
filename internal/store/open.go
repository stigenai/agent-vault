package store

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// StoreConfig carries the parameters for OpenStore.
// If DatabaseURL is non-empty it takes precedence over SQLitePath.
type StoreConfig struct {
	DatabaseURL     string
	SQLitePath      string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnectTimeout  time.Duration
	TLSMode         string
	TLSRootCert     string
	PoolConfigured  bool
}

// OpenStore opens a Store backed by either PostgreSQL or SQLite depending on
// the config. When DatabaseURL is set, it must use the postgres:// or
// postgresql:// scheme. When empty, SQLitePath (or the DefaultDBPath
// fallback) is used for a local SQLite file.
func OpenStore(cfg StoreConfig) (Store, error) {
	if cfg.DatabaseURL == "" {
		path := cfg.SQLitePath
		if path == "" {
			var err error
			path, err = DefaultDBPath()
			if err != nil {
				return nil, fmt.Errorf("resolving default db path: %w", err)
			}
		}
		return Open(path)
	}

	u, err := url.Parse(cfg.DatabaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		scheme := ""
		if u != nil {
			scheme = u.Scheme
		}
		return nil, fmt.Errorf("unrecognized DATABASE_URL scheme %q; supported: postgres://, postgresql://", scheme)
	}

	return openPostgres(cfg)
}

// RedactURL returns a URL string with the password replaced by "***".
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), "***")
		}
	}
	query := u.Query()
	redacted := false
	for key := range query {
		if strings.EqualFold(key, "password") {
			query.Set(key, "***")
			redacted = true
		}
	}
	if redacted {
		u.RawQuery = query.Encode()
	}
	return u.String()
}
