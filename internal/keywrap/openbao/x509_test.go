package openbao

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	spiffetls "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

type rotatingTLSSource struct {
	mu     sync.RWMutex
	config *tls.Config
	cert   tls.Certificate
}

func (s *rotatingTLSSource) ClientTLSConfig(spiffetls.Authorizer) (*tls.Config, error) {
	config := s.config.Clone()
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		cert := s.cert
		return &cert, nil
	}
	return config, nil
}

func (s *rotatingTLSSource) rotate(cert tls.Certificate) {
	s.mu.Lock()
	s.cert = cert
	s.mu.Unlock()
}

func TestX509TokenSourceUsesRotatingClientCertificate(t *testing.T) {
	var mu sync.Mutex
	var serials []string
	revoked := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if revoked {
			http.Error(w, "revoked SECRET-DETAIL", http.StatusForbidden)
			return
		}
		if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
			http.Error(w, "no cert", http.StatusUnauthorized)
			return
		}
		serials = append(serials, req.TLS.PeerCertificates[0].SerialNumber.String())
		_, _ = w.Write([]byte(`{"auth":{"client_token":"short-lived-token"}}`))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	baseTLS := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	first := x509ClientCertificate(t, 1)
	second := x509ClientCertificate(t, 2)
	source := &rotatingTLSSource{config: baseTLS, cert: first}
	tokens, err := NewX509TokenSource(X509Options{
		Address: server.URL, AuthMount: "cert", Role: "agent-vault", Source: source,
		TrustDomains: []spiffeid.TrustDomain{spiffeid.RequireTrustDomainFromString("cluster.example")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.rotate(second)
	tokens.CloseIdleConnections()
	if _, err := tokens.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(serials) != 2 || serials[0] == serials[1] {
		t.Fatalf("login certificate serials = %#v", serials)
	}
	revoked = true
	mu.Unlock()
	tokens.CloseIdleConnections()
	if _, err := tokens.Token(context.Background()); err == nil {
		t.Fatal("revoked OpenBao certificate access was accepted")
	}
}

func x509ClientCertificate(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "SPIFFE test client"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
