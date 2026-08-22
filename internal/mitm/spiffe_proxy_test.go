package mitm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/store"
)

type spiffeAgentLookup map[string]*store.Agent

func (f spiffeAgentLookup) GetAgentBySPIFFEID(_ context.Context, id string) (*store.Agent, error) {
	agent, ok := f[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return agent, nil
}

type capturingAgentResolver struct {
	agentID string
	hint    string
}

func (r *capturingAgentResolver) ResolveAgentForProxy(_ context.Context, agentID, hint string) (*brokercore.ProxyScope, error) {
	r.agentID, r.hint = agentID, hint
	return &brokercore.ProxyScope{AgentID: agentID, VaultID: "vault-1", VaultName: hint, VaultRole: "proxy"}, nil
}

func TestAuthenticateRequestUsesVerifiedSPIFFEActorAndVaultGrant(t *testing.T) {
	const id = "spiffe://cluster.example/ns/agents/sa/worker"
	cert := proxySPIFFECertificate(t, id)
	resolver := &capturingAgentResolver{}
	p := &Proxy{
		agents: spiffeAgentLookup{id: {ID: "agent-1", SPIFFEID: id, Status: "active"}},
		peers:  resolver,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	req.Header.Set("X-Vault", "production")
	req.Header.Set("Proxy-Authorization", "Bearer must-not-be-used")
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}

	scope, err := p.authenticateRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.agentID != "agent-1" || resolver.hint != "production" || scope.ActorID() != "agent-1" {
		t.Fatalf("resolver=(%q,%q) scope=%+v", resolver.agentID, resolver.hint, scope)
	}

	// An identity-looking header without a verified certificate is inert.
	req = httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	req.Header.Set("X-SPIFFE-ID", id)
	if _, err := p.authenticateRequest(req); !errors.Is(err, brokercore.ErrInvalidSession) {
		t.Fatalf("spoofed identity header: %v", err)
	}
}

func TestAuthenticateRequestSPIFFEOnlyRejectsBearer(t *testing.T) {
	p := &Proxy{
		spiffeOnly: true,
		sessions:   validTokenResolver("legacy", &brokercore.ProxyScope{AgentID: "legacy-agent", VaultID: "vault-1"}),
	}
	req := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	req.Header.Set("Proxy-Authorization", "Bearer legacy")
	if _, err := p.authenticateRequest(req); !errors.Is(err, brokercore.ErrInvalidSession) {
		t.Fatalf("SPIFFE-only proxy accepted bearer: %v", err)
	}
}

func TestSPIFFEForwardAuditUsesBackingAgentIdentity(t *testing.T) {
	const id = "spiffe://cluster.example/ns/agents/sa/worker"
	cert := proxySPIFFECertificate(t, id)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	resolver := &capturingAgentResolver{}
	sink := &recordingSink{}
	p := New("127.0.0.1:0", Options{
		Peers:      resolver,
		Agents:     spiffeAgentLookup{id: {ID: "agent-spiffe", SPIFFEID: id, Status: "active"}},
		SPIFFEOnly: true,
		Credentials: &fakeCredProvider{byHost: map[string]fakeInjectResult{
			upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
		}},
		Logger:                  slog.New(slog.DiscardHandler),
		RateLimit:               ratelimit.New(ratelimit.DefaultsFor(ratelimit.ProfileOff)),
		LogSink:                 sink,
		AllowPrivateRanges:      true,
		NetworkPolicyConfigured: true,
	})

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/audit", nil)
	req.Header.Set("X-Vault", "production")
	req.Header.Set("Proxy-Authorization", "Bearer must-not-be-used")
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
	rec := httptest.NewRecorder()
	p.dispatch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward status = %d, want 200", rec.Code)
	}

	rows := sink.snapshot()
	if len(rows) != 1 {
		t.Fatalf("audit records = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ActorType != brokercore.ActorTypeAgent || row.ActorID != "agent-spiffe" {
		t.Fatalf("audit actor = %q/%q, want agent/agent-spiffe", row.ActorType, row.ActorID)
	}
	if row.VaultID != "vault-1" {
		t.Fatalf("audit vault = %q, want vault-1", row.VaultID)
	}
	if resolver.agentID != "agent-spiffe" || resolver.hint != "production" {
		t.Fatalf("resolver input = %q/%q, want agent-spiffe/production", resolver.agentID, resolver.hint)
	}
}

func proxySPIFFECertificate(t *testing.T, rawID string) *x509.Certificate {
	t.Helper()
	uri, err := url.Parse(rawID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: rawID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
