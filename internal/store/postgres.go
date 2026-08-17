package store

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
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
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

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
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	if err := runGORMMigrations(db, "postgres"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &SQLStore{db: db, dialect: PostgresDialect{}}, nil
}
