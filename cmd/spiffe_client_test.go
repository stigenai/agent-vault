package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/session"
)

func TestEnsureSessionUsesEphemeralWorkloadIdentityWithoutPersistence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	original := loadWorkloadIdentitySession
	loadWorkloadIdentitySession = func() (*session.ClientSession, error) {
		return &session.ClientSession{Address: "https://vault.example", WorkloadIdentity: true}, nil
	}
	t.Cleanup(func() { loadWorkloadIdentitySession = original })

	sess, err := ensureSession()
	if err != nil {
		t.Fatal(err)
	}
	if !sess.WorkloadIdentity || sess.Token != "" {
		t.Fatalf("session = %+v", sess)
	}
	path := filepath.Join(os.Getenv("HOME"), ".agent-vault", "session.json")
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workload identity persisted a session file: %v", err)
	}
}

func TestWorkloadIdentityRequestSendsNoBearerHeader(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	previous := httpClient.Transport
	httpClient.Transport = defaultCLITransport()
	t.Cleanup(func() { httpClient.Transport = previous })

	if _, err := doVaultScopedRequestWithBody(http.MethodGet, server.URL, "", "default", nil); err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		t.Fatalf("Authorization header = %q", authorization)
	}
}

func TestWorkloadIdentityNeverFallsBackToPasswordReauth(t *testing.T) {
	originalInteractive, originalReauth := isInteractiveFn, reauthFn
	isInteractiveFn = func() bool { return true }
	reauthCalls := 0
	reauthFn = func(*session.ClientSession) (*session.ClientSession, error) {
		reauthCalls++
		return nil, errors.New("must not be called")
	}
	t.Cleanup(func() {
		isInteractiveFn, reauthFn = originalInteractive, originalReauth
	})

	sess := &session.ClientSession{Address: "https://vault.example", WorkloadIdentity: true}
	err := withReauthRetry(sess, sess.Address, func(*session.ClientSession) error { return errSessionExpired })
	if !errors.Is(err, errSessionExpired) || reauthCalls != 0 {
		t.Fatalf("error=%v reauthCalls=%d", err, reauthCalls)
	}
}
