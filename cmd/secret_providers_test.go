package cmd

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestAttachSecretProvidersBuildsTypedOnePasswordWorker(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "providers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ref, err := runtimeconfig.ParseSecretRef("file:///var/run/secrets/onepassword/connect-token")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New("127.0.0.1:0", database, make([]byte, 32), nil, true, "https://agent-vault.example", logger)
	cfg := runtimeconfig.Defaults()
	cfg.SecretProviders = []runtimeconfig.SecretProviderConfig{{
		Name: "onepassword", Kind: "onepassword-connect", Address: "https://connect.example", Token: ref,
	}}
	if err := attachSecretProviders(srv, cfg, make([]byte, 32), database, logger, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAttachSecretProvidersFailsClosedWithoutRequiredIdentity(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "providers-fail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New("127.0.0.1:0", database, make([]byte, 32), nil, true, "https://agent-vault.example", logger)
	cfg := runtimeconfig.Defaults()
	cfg.Auth = runtimeconfig.Auth{
		Mode: "spiffe", WorkloadAPI: "unix:///run/spire/sockets/agent.sock", TrustDomains: []string{"spiffe://cluster.example"},
	}
	cfg.SecretProviders = []runtimeconfig.SecretProviderConfig{{
		Name: "bao", Kind: "openbao-kv-v2", Address: "https://openbao.example",
		Auth: "spiffe-x509", Role: "agent-vault",
	}}
	err = attachSecretProviders(srv, cfg, make([]byte, 32), database, logger, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires SPIFFE X.509 identity") {
		t.Fatalf("missing identity error = %v", err)
	}
}

func TestSecretRefreshWorkerIDsAreReplicaUnique(t *testing.T) {
	first := secretRefreshWorkerID()
	second := secretRefreshWorkerID()
	if first == "" || second == "" || first == second || strings.ContainsAny(first+second, "\r\n\x00") {
		t.Fatalf("worker IDs = %q, %q", first, second)
	}
}
