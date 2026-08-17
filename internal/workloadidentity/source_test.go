package workloadidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type fakeMaterialSource struct {
	mu      sync.RWMutex
	svid    *x509svid.SVID
	err     error
	updates chan struct{}
}

func (f *fakeMaterialSource) GetX509SVID() (*x509svid.SVID, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.svid, f.err
}

func (f *fakeMaterialSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, nil
}

func (f *fakeMaterialSource) Updated() <-chan struct{} { return f.updates }

func (f *fakeMaterialSource) rotate(svid *x509svid.SVID) {
	f.mu.Lock()
	f.svid = svid
	f.mu.Unlock()
	select {
	case f.updates <- struct{}{}:
	default:
	}
}

func TestSourceReadinessIdentityAndRotation(t *testing.T) {
	now := time.Now().UTC()
	first := testSVID(t, "spiffe://cluster.example/ns/agents/sa/one", now.Add(-time.Minute), now.Add(time.Hour))
	second := testSVID(t, "spiffe://cluster.example/ns/agents/sa/two", now.Add(-time.Minute), now.Add(2*time.Hour))
	fake := &fakeMaterialSource{svid: first, updates: make(chan struct{}, 1)}
	closed := 0
	source := newSource(fake, func() error { closed++; return nil })
	source.now = func() time.Time { return now }

	if err := source.Ready(); err != nil {
		t.Fatal(err)
	}
	if id, err := source.ID(); err != nil || id.String() != first.ID.String() {
		t.Fatalf("ID = %v, %v", id, err)
	}
	clientTLS, err := source.ClientTLSConfig(tlsconfig.AuthorizeAny())
	if err != nil {
		t.Fatal(err)
	}
	firstTLS, err := clientTLS.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	fake.rotate(second)
	select {
	case <-source.Updated():
	default:
		t.Fatal("rotation update was not signalled")
	}
	secondTLS, err := clientTLS.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstTLS.Certificate[0]) == string(secondTLS.Certificate[0]) {
		t.Fatal("TLS callback retained stale SVID after rotation")
	}
	if id, err := source.ID(); err != nil || id.String() != second.ID.String() {
		t.Fatalf("rotated ID = %v, %v", id, err)
	}

	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil || closed != 1 {
		t.Fatalf("idempotent close = %v, calls=%d", err, closed)
	}
}

func TestSourceBecomesUnreadyWhenSVIDExpires(t *testing.T) {
	now := time.Now().UTC()
	fake := &fakeMaterialSource{
		svid:    testSVID(t, "spiffe://cluster.example/workload", now.Add(-time.Hour), now.Add(time.Minute)),
		updates: make(chan struct{}, 1),
	}
	source := newSource(fake, nil)
	source.now = func() time.Time { return now }
	if err := source.Ready(); err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now.Add(2 * time.Minute) }
	if err := source.Ready(); err == nil {
		t.Fatal("expired SVID remained ready")
	}
	if _, err := source.ClientTLSConfig(tlsconfig.AuthorizeAny()); err == nil {
		t.Fatal("expired SVID produced client TLS config")
	}
}

func TestNewHonorsCancelledContextAndValidatesSocket(t *testing.T) {
	for _, address := range []string{"", "tcp://spire:8081", "unix://relative.sock", "unix:///tmp/../relative.sock"} {
		if err := validateAddress(address); err == nil {
			t.Errorf("address %q accepted", address)
		}
	}
	if err := validateAddress("unix:///run/spire/sockets/agent.sock"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx, Options{Address: "unix:///tmp/does-not-exist.sock"}); err == nil {
		t.Fatal("cancelled connection returned no error")
	}
}

func testSVID(t *testing.T, rawID string, notBefore, notAfter time.Time) *x509svid.SVID {
	t.Helper()
	id, err := spiffeid.FromString(rawID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.UnixNano()),
		Subject:      pkix.Name{CommonName: rawID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{id.URL()},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}
