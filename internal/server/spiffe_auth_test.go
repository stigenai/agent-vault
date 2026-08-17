package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestRequireAuthMapsVerifiedSPIFFEPeerAndResistsDowngrade(t *testing.T) {
	const id = "spiffe://cluster.example/ns/agents/sa/worker"
	cert := spiffeTestCertificate(t, id)
	ms := newMockStore()
	ms.agents["worker"] = &store.Agent{ID: "agent-1", Name: "worker", SPIFFEID: id, Status: "active"}
	ms.sessions["legacy"] = &store.Session{ID: "session-1", AgentID: "legacy-agent"}
	srv := newTestServer(withStore(ms))

	var actorID string
	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		actorID = sessionFromContext(r.Context()).AgentID
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusNoContent || actorID != "agent-1" {
		t.Fatalf("verified peer: status=%d actor=%q body=%s", rr.Code, actorID, rr.Body.String())
	}

	// An identity-looking header is never an authentication source.
	req = httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("X-SPIFFE-ID", id)
	rr = httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed identity header status = %d", rr.Code)
	}

	// A presented but unknown certificate cannot downgrade to a valid token.
	unknown := spiffeTestCertificate(t, "spiffe://cluster.example/unknown")
	req = httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer legacy")
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{unknown},
		VerifiedChains:    [][]*x509.Certificate{{unknown}},
	}
	rr = httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unknown certificate downgraded to bearer: status=%d", rr.Code)
	}

	// Legacy listeners retain bearer compatibility when no certificate is
	// presented; SPIFFE-only policy is layered on in the next migration task.
	req = httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer legacy")
	rr = httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusNoContent || actorID != "legacy-agent" {
		t.Fatalf("legacy bearer: status=%d actor=%q", rr.Code, actorID)
	}
}

func spiffeTestCertificate(t *testing.T, rawID string) *x509.Certificate {
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
