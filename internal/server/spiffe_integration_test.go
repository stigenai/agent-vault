package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func TestSPIFFEOnlyListenerDowngradeRoleRotationAndRevocation(t *testing.T) {
	clusterDomain := spiffeid.RequireTrustDomainFromString("cluster.example")
	clusterCA := newIntegrationCA(t, "cluster.example")
	otherCA := newIntegrationCA(t, "other.example")
	bundles := x509bundle.NewSet(x509bundle.FromX509Authorities(clusterDomain, []*x509.Certificate{clusterCA.cert}))

	serverCert, _ := clusterCA.issue(t, "spiffe://cluster.example/ns/vault/sa/server")
	workerCert1, _ := clusterCA.issue(t, "spiffe://cluster.example/ns/operators/sa/worker")
	workerCert2, _ := clusterCA.issue(t, "spiffe://cluster.example/ns/operators/sa/worker")
	memberCert, _ := clusterCA.issue(t, "spiffe://cluster.example/ns/operators/sa/member")
	ownerCert, _ := clusterCA.issue(t, "spiffe://cluster.example/ns/operators/sa/owner")
	unknownCert, _ := clusterCA.issue(t, "spiffe://cluster.example/ns/operators/sa/unknown")
	wrongDomainCert, _ := otherCA.issue(t, "spiffe://other.example/ns/operators/sa/owner")

	ms := newMockStore()
	ms.agents["worker"] = &store.Agent{ID: "agent-worker", Name: "worker", SPIFFEID: "spiffe://cluster.example/ns/operators/sa/worker", Role: "member", Status: "active"}
	ms.agents["member"] = &store.Agent{ID: "agent-member", Name: "member", SPIFFEID: "spiffe://cluster.example/ns/operators/sa/member", Role: "member", Status: "active"}
	ms.agents["owner"] = &store.Agent{ID: "agent-owner", Name: "owner", SPIFFEID: "spiffe://cluster.example/ns/operators/sa/owner", Role: "owner", Status: "active"}
	ms.sessions["legacy-token"] = &store.Session{ID: "legacy", AgentID: "agent-owner"}

	authorizer := workloadidentity.AuthorizeAgents(ms, clusterDomain)
	verifyClient := tlsconfig.VerifyPeerCertificate(bundles, authorizer)
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}
			return verifyClient(rawCerts, chains)
		},
	}
	srv := NewWithRuntime("127.0.0.1:0", ms, make([]byte, 32), nil, true, "https://vault.test", slog.New(slog.DiscardHandler), RuntimeOptions{
		TLSConfig:      serverTLS,
		AuthMode:       "spiffe",
		RateLimit:      ratelimit.DefaultsFor(ratelimit.ProfileOff),
		MetricsEnabled: true,
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.httpServer.Shutdown(ctx)
		<-done
	})
	baseURL := "https://" + listener.Addr().String()

	// Kubernetes health probes may complete TLS without a client SVID, but a
	// protected route cannot downgrade to a valid legacy bearer token.
	noCert := integrationClient(t, bundles, nil)
	resp := integrationRequest(t, noCert, http.MethodGet, baseURL+"/health", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("certificate-less health status = %d", resp.StatusCode)
	}
	closeIntegrationResponse(resp)
	resp = integrationRequest(t, noCert, http.MethodGet, baseURL+"/v1/auth/me", "legacy-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("certificate-less bearer downgrade status = %d", resp.StatusCode)
	}
	closeIntegrationResponse(resp)

	for name, cert := range map[string]tls.Certificate{
		"unknown exact ID":   unknownCert,
		"wrong trust domain": wrongDomainCert,
	} {
		t.Run(name, func(t *testing.T) {
			client := integrationClient(t, bundles, &cert)
			req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/auth/me", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer legacy-token")
			req.Header.Set("X-SPIFFE-ID", ms.agents["owner"].SPIFFEID)
			if _, err := client.Do(req); err == nil {
				t.Fatal("invalid presented SVID completed TLS using spoofed header or bearer token")
			}
		})
	}

	memberClient := integrationClient(t, bundles, &memberCert)
	resp = integrationRequest(t, memberClient, http.MethodGet, baseURL+"/v1/admin/settings", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member accessed owner route: status=%d", resp.StatusCode)
	}
	closeIntegrationResponse(resp)
	ownerClient := integrationClient(t, bundles, &ownerCert)
	resp = integrationRequest(t, ownerClient, http.MethodGet, baseURL+"/v1/admin/settings", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("owner route status=%d body=%s", resp.StatusCode, body)
	}
	closeIntegrationResponse(resp)
	resp = integrationRequest(t, ownerClient, http.MethodGet, baseURL+"/metrics", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("SPIFFE-authenticated metrics status=%d body=%s", resp.StatusCode, body)
	}
	closeIntegrationResponse(resp)

	// The client callback changes certificate material without replacing the
	// HTTP client or listener, matching live SPIRE rotation behavior.
	var rotating struct {
		sync.RWMutex
		cert tls.Certificate
	}
	rotating.cert = workerCert1
	workerClient := integrationClient(t, bundles, nil)
	workerTransport := workerClient.Transport.(*http.Transport)
	workerTransport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		rotating.RLock()
		defer rotating.RUnlock()
		cert := rotating.cert
		return &cert, nil
	}
	resp = integrationRequest(t, workerClient, http.MethodGet, baseURL+"/v1/auth/me", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first rotating identity status = %d", resp.StatusCode)
	}
	closeIntegrationResponse(resp)
	rotating.Lock()
	rotating.cert = workerCert2
	rotating.Unlock()
	workerTransport.CloseIdleConnections()
	resp = integrationRequest(t, workerClient, http.MethodGet, baseURL+"/v1/auth/me", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotated identity status = %d", resp.StatusCode)
	}
	closeIntegrationResponse(resp)

	// Revocation is checked per request, so it invalidates even a reused TLS
	// connection whose handshake previously succeeded.
	ms.agents["worker"].Status = "revoked"
	revokedAt := time.Now().UTC()
	ms.agents["worker"].RevokedAt = &revokedAt
	resp = integrationRequest(t, workerClient, http.MethodGet, baseURL+"/v1/auth/me", "legacy-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked connection downgraded or remained active: status=%d", resp.StatusCode)
	}
	closeIntegrationResponse(resp)
}

func closeIntegrationResponse(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

type integrationCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newIntegrationCA(t *testing.T, name string) integrationCA {
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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return integrationCA{cert: cert, key: key}
}

func (ca integrationCA) issue(t *testing.T, rawID string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	id, err := url.Parse(rawID)
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
		URIs:         []*url.URL{id},
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert
}

func integrationClient(t *testing.T, bundles *x509bundle.Set, cert *tls.Certificate) *http.Client {
	t.Helper()
	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // go-spiffe verifies the URI SAN and bundle below.
		VerifyPeerCertificate: tlsconfig.VerifyPeerCertificate(
			bundles,
			workloadidentity.AuthorizeTrustDomains(spiffeid.RequireTrustDomainFromString("cluster.example")),
		),
	}
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}, Timeout: 3 * time.Second}
}

func integrationRequest(t *testing.T, client *http.Client, method, target, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", target, err)
	}
	return resp
}
