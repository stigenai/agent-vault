package substrate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/substrate/credproviderpb"
)

const (
	grantedActor   = "spiffe://substrate-actor.local/actor/team-a/coder"
	ungrantedActor = "spiffe://substrate-actor.local/actor/team-b/intruder"
	revokedActor   = "spiffe://substrate-actor.local/actor/team-a/revoked"
)

type fakeStore struct {
	agents map[string]*store.Agent
	vaults map[string]*store.Vault
	grants map[[2]string]string
	creds  map[[2]string]*store.Credential
	err    error
}

func (f *fakeStore) GetAgentBySPIFFEID(_ context.Context, id string) (*store.Agent, error) {
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.agents[id]; ok {
		return a, nil
	}
	return nil, sql.ErrNoRows
}

func (f *fakeStore) GetVault(_ context.Context, name string) (*store.Vault, error) {
	if v, ok := f.vaults[name]; ok {
		return v, nil
	}
	return nil, sql.ErrNoRows
}

func (f *fakeStore) GetVaultRole(_ context.Context, actorID, vaultID string) (string, error) {
	if r, ok := f.grants[[2]string{actorID, vaultID}]; ok {
		return r, nil
	}
	return "", sql.ErrNoRows
}

func (f *fakeStore) GetCredential(_ context.Context, vaultID, key string) (*store.Credential, error) {
	if c, ok := f.creds[[2]string{vaultID, key}]; ok {
		return c, nil
	}
	return nil, sql.ErrNoRows
}

func newFixture(t *testing.T) (*Provider, *fakeStore) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := crypto.Encrypt([]byte("vault-token-123"), key)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Now()
	fs := &fakeStore{
		agents: map[string]*store.Agent{
			grantedActor:   {ID: "ag1", SPIFFEID: grantedActor, Status: "active"},
			ungrantedActor: {ID: "ag2", SPIFFEID: ungrantedActor, Status: "active"},
			revokedActor:   {ID: "ag3", SPIFFEID: revokedActor, Status: "revoked", RevokedAt: &revokedAt},
		},
		vaults: map[string]*store.Vault{"team-a": {ID: "v1", Name: "team-a"}},
		grants: map[[2]string]string{{"ag1", "v1"}: "proxy", {"ag3", "v1"}: "proxy"},
		creds: map[[2]string]*store.Credential{
			{"v1", "GITHUB_TOKEN"}: {VaultID: "v1", Key: "GITHUB_TOKEN", Type: "static", Ciphertext: ct, Nonce: nonce},
		},
	}
	return NewProvider(fs, key, DefaultActorTrustDomain), fs
}

func TestParseURI(t *testing.T) {
	ok := map[string]SecretRef{
		"ate-secret://agent-vault/team-a/GITHUB_TOKEN": {Vault: "team-a", Key: "GITHUB_TOKEN"},
		"ate-secret://agent-vault/default/x":           {Vault: "default", Key: "x"},
	}
	for raw, want := range ok {
		got, err := ParseURI(raw)
		if err != nil || got != want {
			t.Errorf("ParseURI(%q) = %+v, %v; want %+v", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"",
		"https://agent-vault/team-a/KEY",
		"ate-secret://k8s.io/team-a/KEY",
		"ate-secret://agent-vault/team-a",
		"ate-secret://agent-vault/team-a/KEY/extra",
		"ate-secret://agent-vault//KEY",
		"ate-secret://agent-vault/team-a/KEY?x=1",
		"ate-secret://agent-vault/team-a/KEY#frag",
		"ate-secret://agent-vault/team%2Da/KEY",
		"ate-secret://user@agent-vault/team-a/KEY",
	} {
		if _, err := ParseURI(raw); err == nil {
			t.Errorf("ParseURI(%q) succeeded; want error", raw)
		}
	}
}

func TestFetchSecret(t *testing.T) {
	cases := []struct {
		name  string
		uri   string
		actor string
		code  codes.Code
	}{
		{"granted", "ate-secret://agent-vault/team-a/GITHUB_TOKEN", grantedActor, codes.OK},
		{"ungranted actor", "ate-secret://agent-vault/team-a/GITHUB_TOKEN", ungrantedActor, codes.PermissionDenied},
		{"unregistered actor", "ate-secret://agent-vault/team-a/GITHUB_TOKEN", "spiffe://substrate-actor.local/actor/team-a/ghost", codes.PermissionDenied},
		{"revoked actor", "ate-secret://agent-vault/team-a/GITHUB_TOKEN", revokedActor, codes.PermissionDenied},
		{"foreign trust domain", "ate-secret://agent-vault/team-a/GITHUB_TOKEN", "spiffe://nixfleet.stigen.ai/actor/team-a/coder", codes.PermissionDenied},
		{"empty actor", "ate-secret://agent-vault/team-a/GITHUB_TOKEN", "", codes.PermissionDenied},
		{"unknown vault hides existence", "ate-secret://agent-vault/nope/GITHUB_TOKEN", grantedActor, codes.PermissionDenied},
		{"missing key after authz", "ate-secret://agent-vault/team-a/MISSING", grantedActor, codes.NotFound},
		{"wrong provider", "ate-secret://k8s.io/default/ns/s/k", grantedActor, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newFixture(t)
			resp, err := p.FetchSecret(context.Background(), &credproviderpb.FetchSecretRequest{Uri: tc.uri, ActorSpiffeId: tc.actor})
			if got := status.Code(err); got != tc.code {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.code)
			}
			if tc.code == codes.OK && string(resp.GetOpaqueBytes()) != "vault-token-123" {
				t.Fatalf("secret = %q", resp.GetOpaqueBytes())
			}
			if tc.code != codes.OK && resp != nil {
				t.Fatalf("non-OK response carried a payload")
			}
		})
	}
}

func TestFetchSecretStoreOutageIsUnavailable(t *testing.T) {
	p, fs := newFixture(t)
	fs.err = errors.New("connection refused")
	_, err := p.FetchSecret(context.Background(), &credproviderpb.FetchSecretRequest{
		Uri: "ate-secret://agent-vault/team-a/GITHUB_TOKEN", ActorSpiffeId: grantedActor,
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestFetchSecretUnconnectedOAuthIsNotFound(t *testing.T) {
	p, fs := newFixture(t)
	ct, nonce, _ := crypto.Encrypt([]byte(""), p.encKey)
	fs.creds[[2]string{"v1", "OAUTH"}] = &store.Credential{Type: "oauth", Ciphertext: ct, Nonce: nonce}
	_, err := p.FetchSecret(context.Background(), &credproviderpb.FetchSecretRequest{
		Uri: "ate-secret://agent-vault/team-a/OAUTH", ActorSpiffeId: grantedActor,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

// --- mTLS ---

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// bundle issues a leaf and returns it as a PEM credential bundle (key then
// chain), the format podCertificate projections write.
func (ca testCA) bundle(t *testing.T, dns string, uri string, eku x509.ExtKeyUsage) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	if dns != "" {
		tmpl.DNSNames = []string{dns}
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMTLSAdmitsOnlyGatewayIdentity(t *testing.T) {
	dir := t.TempDir()
	serverCA, clientCA, rogueCA := newCA(t), newCA(t), newCA(t)
	const serverName = "agent-vault.six-city-agent-vault.svc"

	tlsCfg, err := ServerTLSConfig(TLSFiles{
		ServerCredBundle: writeFile(t, dir, "server.pem", serverCA.bundle(t, serverName, "", x509.ExtKeyUsageServerAuth)),
		ClientCAFile:     writeFile(t, dir, "client-ca.pem", clientCA.pem),
		GatewayIdentity:  DefaultGatewayIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := newFixture(t)
	gs := NewGRPCServer(p, tlsCfg)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	fetch := func(clientBundle []byte) error {
		roots := x509.NewCertPool()
		roots.AddCert(serverCA.cert)
		cfg := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13}
		if clientBundle != nil {
			c, err := tls.X509KeyPair(clientBundle, clientBundle)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Certificates = []tls.Certificate{c}
		}
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = credproviderpb.NewCredentialProviderClient(conn).FetchSecret(ctx, &credproviderpb.FetchSecretRequest{
			Uri: "ate-secret://agent-vault/team-a/GITHUB_TOKEN", ActorSpiffeId: grantedActor,
		})
		return err
	}

	if err := fetch(clientCA.bundle(t, "", DefaultGatewayIdentity, x509.ExtKeyUsageClientAuth)); err != nil {
		t.Fatalf("gateway identity rejected: %v", err)
	}
	if err := fetch(clientCA.bundle(t, "", "spiffe://cluster.local/ns/ate-system/sa/other", x509.ExtKeyUsageClientAuth)); err == nil {
		t.Fatal("other SAN from the trusted CA was admitted")
	}
	if err := fetch(rogueCA.bundle(t, "", DefaultGatewayIdentity, x509.ExtKeyUsageClientAuth)); err == nil {
		t.Fatal("gateway SAN from an untrusted CA was admitted")
	}
	if err := fetch(nil); err == nil {
		t.Fatal("caller without a client certificate was admitted")
	}
}

func TestServerTLSConfigRequiresFiles(t *testing.T) {
	if _, err := ServerTLSConfig(TLSFiles{GatewayIdentity: DefaultGatewayIdentity}); err == nil {
		t.Fatal("missing files accepted")
	}
	dir := t.TempDir()
	if _, err := ServerTLSConfig(TLSFiles{
		ServerCredBundle: "/nonexistent", ClientCAFile: writeFile(t, dir, "empty.pem", nil), GatewayIdentity: DefaultGatewayIdentity,
	}); err == nil {
		t.Fatal("empty client CA accepted")
	}
}
