package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestSPIFFEDialRotatesIdentityAndSendsNoBearerToken(t *testing.T) {
	domain := spiffeid.RequireTrustDomainFromString("cluster.example")
	ca := newRelayCA(t, "cluster.example")
	bundle := x509bundle.FromX509Authorities(domain, []*x509.Certificate{ca.cert})
	client1 := ca.issueSVID(t, "spiffe://cluster.example/ns/agents/sa/worker")
	client2 := ca.issueSVID(t, "spiffe://cluster.example/ns/agents/sa/worker")
	serverSVID := ca.issueSVID(t, "spiffe://cluster.example/ns/vault/sa/proxy")
	clientMaterial := &relayMaterial{svid: client1, bundle: bundle}
	serverMaterial := &relayMaterial{svid: serverSVID, bundle: bundle}

	centralTLS := tlsconfig.MTLSServerConfig(serverMaterial, serverMaterial, workloadidentity.AuthorizeAgents(
		relayAgentLookup{id: client1.ID.String(), agentID: "agent-worker"}, domain,
	))
	central := newCentralSPIFFEProxy(t, centralTLS)
	clientTLS := tlsconfig.MTLSClientConfig(clientMaterial, clientMaterial, workloadidentity.AuthorizeTrustDomains(domain))
	dial, err := newMTLSDialContext(clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayAddr, _ := startRelay(t, central.Addr().String(), dial)
	transport := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: relayAddr}),
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport}

	first := relaySPIFFERequest(t, client)
	clientMaterial.rotate(client2)
	second := relaySPIFFERequest(t, client)
	if first == second {
		t.Fatalf("central proxy saw unchanged SVID serial after rotation: %s", first)
	}
}

func TestSPIFFEDialRejectsUntrustedBrokerIdentity(t *testing.T) {
	clusterDomain := spiffeid.RequireTrustDomainFromString("cluster.example")
	otherDomain := spiffeid.RequireTrustDomainFromString("other.example")
	clusterCA := newRelayCA(t, "cluster.example")
	otherCA := newRelayCA(t, "other.example")
	clientMaterial := &relayMaterial{
		svid:   clusterCA.issueSVID(t, "spiffe://cluster.example/ns/agents/sa/worker"),
		bundle: x509bundle.FromX509Authorities(clusterDomain, []*x509.Certificate{clusterCA.cert}),
	}
	serverMaterial := &relayMaterial{
		svid:   otherCA.issueSVID(t, "spiffe://other.example/ns/vault/sa/proxy"),
		bundle: x509bundle.FromX509Authorities(otherDomain, []*x509.Certificate{otherCA.cert}),
	}
	central := newCentralSPIFFEProxy(t, tlsconfig.MTLSServerConfig(serverMaterial, serverMaterial, tlsconfig.AuthorizeAny()))
	clientTLS := tlsconfig.MTLSClientConfig(clientMaterial, clientMaterial, workloadidentity.AuthorizeTrustDomains(clusterDomain))
	dial, err := newMTLSDialContext(clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayAddr, _ := startRelay(t, central.Addr().String(), dial)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: relayAddr})}}
	resp, err := client.Get("http://service.example/fail-closed")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted broker status = %d, want 502", resp.StatusCode)
	}
}

func relaySPIFFERequest(t *testing.T, client *http.Client) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://service.example/identity", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay request status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Proxy-Authorization"); got != "" {
		t.Fatalf("relay sent durable proxy authorization: %q", got)
	}
	if got := resp.Header.Get("X-SPIFFE-ID"); got != "spiffe://cluster.example/ns/agents/sa/worker" {
		t.Fatalf("central peer identity = %q", got)
	}
	return resp.Header.Get("X-SVID-Serial")
}

func newCentralSPIFFEProxy(t *testing.T, tlsConfig *tls.Config) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, tlsConfig)
	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if got := req.Header.Get("Proxy-Authorization"); got != "" {
				w.Header().Set("X-Proxy-Authorization", got)
			}
			if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
				http.Error(w, "missing peer SVID", http.StatusUnauthorized)
				return
			}
			id, err := x509svid.IDFromCert(req.TLS.PeerCertificates[0])
			if err != nil {
				http.Error(w, "invalid peer SVID", http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-SPIFFE-ID", id.String())
			w.Header().Set("X-SVID-Serial", req.TLS.PeerCertificates[0].SerialNumber.String())
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return listener
}

type relayMaterial struct {
	mu     sync.RWMutex
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
	err    error
}

type relayAgentLookup struct {
	id      string
	agentID string
}

func (l relayAgentLookup) GetAgentBySPIFFEID(_ context.Context, id string) (*store.Agent, error) {
	if id != l.id {
		return nil, sql.ErrNoRows
	}
	return &store.Agent{ID: l.agentID, SPIFFEID: l.id, Status: "active"}, nil
}

func (m *relayMaterial) GetX509SVID() (*x509svid.SVID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.err != nil {
		return nil, m.err
	}
	return m.svid, nil
}

func (m *relayMaterial) GetX509BundleForTrustDomain(domain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.err != nil {
		return nil, m.err
	}
	if m.bundle == nil || m.bundle.TrustDomain() != domain {
		return nil, fmt.Errorf("bundle not found")
	}
	return m.bundle, nil
}

func (m *relayMaterial) setError(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

func (m *relayMaterial) rotate(svid *x509svid.SVID) {
	m.mu.Lock()
	m.svid = svid
	m.mu.Unlock()
}

type relayCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newRelayCA(t *testing.T, name string) relayCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: name + " root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return relayCA{cert: cert, key: key}
}

func (ca relayCA) issueSVID(t *testing.T, rawID string) *x509svid.SVID {
	t.Helper()
	id := spiffeid.RequireFromString(rawID)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	serial := big.NewInt(now.UnixNano())
	serial.Add(serial, big.NewInt(int64(len(rawID))))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: rawID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*url.URL{id.URL()},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert, ca.cert}, PrivateKey: key}
}

func TestNewSPIFFEDialContextValidatesRequiredInputs(t *testing.T) {
	if _, err := NewSPIFFEDialContext(SPIFFEDialOptions{}); err == nil {
		t.Fatal("nil source was accepted")
	}
	if _, err := newMTLSDialContext(nil, nil); err == nil {
		t.Fatal("nil TLS configuration was accepted")
	}
}
