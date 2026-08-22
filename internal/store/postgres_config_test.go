package store

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConfigurePostgresURLAppliesVerifiedTLSAndTimeout(t *testing.T) {
	raw := "postgres://agentvault:secret@db.example/agentvault?application_name=agent-vault"
	configured, err := configurePostgresURL(raw, "verify-full", "/var/run/secrets/postgres/ca.crt", 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(configured)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("sslmode") != "verify-full" || query.Get("sslrootcert") != "/var/run/secrets/postgres/ca.crt" {
		t.Fatalf("TLS query = %v", query)
	}
	if query.Get("connect_timeout") != "2" {
		t.Fatalf("connect timeout = %q, want rounded-up 2 seconds", query.Get("connect_timeout"))
	}
	if query.Get("application_name") != "agent-vault" {
		t.Fatalf("existing query parameter lost: %v", query)
	}
}

func TestConfigurePostgresURLRejectsTLSConflicts(t *testing.T) {
	for _, test := range []struct {
		name, raw, mode, root string
	}{
		{"mode", "postgres://db/app?sslmode=require", "verify-full", "/ca.crt"},
		{"root", "postgres://db/app?sslmode=verify-full&sslrootcert=/old.crt", "verify-full", "/new.crt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := configurePostgresURL(test.raw, test.mode, test.root, 10*time.Second); err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("conflict error = %v", err)
			}
		})
	}
}

func TestValidatePostgresRuntimeBounds(t *testing.T) {
	valid := func() error {
		return validatePostgresRuntime(25, 10, 5*time.Minute, 10*time.Second, "verify-full", "/ca.crt")
	}
	if err := valid(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
	}{
		{"unbounded open", validatePostgresRuntime(0, 0, 5*time.Minute, 10*time.Second, "", "")},
		{"excess open", validatePostgresRuntime(1001, 10, 5*time.Minute, 10*time.Second, "", "")},
		{"excess idle", validatePostgresRuntime(10, 11, 5*time.Minute, 10*time.Second, "", "")},
		{"short lifetime", validatePostgresRuntime(10, 5, time.Second, 10*time.Second, "", "")},
		{"long timeout", validatePostgresRuntime(10, 5, 5*time.Minute, 2*time.Minute, "", "")},
		{"unverified root", validatePostgresRuntime(10, 5, 5*time.Minute, 10*time.Second, "require", "/ca.crt")},
		{"relative root", validatePostgresRuntime(10, 5, 5*time.Minute, 10*time.Second, "verify-ca", "ca.crt")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.err == nil {
				t.Fatal("invalid PostgreSQL runtime accepted")
			}
		})
	}
}

func TestSanitizePostgresDiagnosticRemovesCredentials(t *testing.T) {
	raw := "postgres://operator:p%40ss-word@db.example/agentvault?sslmode=verify-full"
	diagnostic := errors.New("dial failed for postgres://operator:p%40ss-word@db.example/agentvault and password p@ss-word")
	got := sanitizePostgresDiagnostic(diagnostic, raw)
	for _, secret := range []string{"p%40ss-word", "p@ss-word"} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "operator:***@db.example") {
		t.Fatalf("diagnostic lost useful redacted endpoint: %s", got)
	}
}

func TestSanitizePostgresDiagnosticRedactsQueryPassword(t *testing.T) {
	raw := "postgres://operator@db.example/agentvault?password=query-secret&sslmode=verify-full"
	got := sanitizePostgresDiagnostic(errors.New("connection failed: "+raw+" password query-secret"), raw)
	if strings.Contains(got, "query-secret") {
		t.Fatalf("sanitized diagnostic leaked query password: %q", got)
	}
	if !strings.Contains(got, "password=%2A%2A%2A") {
		t.Fatalf("sanitized diagnostic did not retain a redacted URL: %q", got)
	}
}
