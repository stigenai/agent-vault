package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/contracttest"
)

const keyRef = "Personal Agents/app/private_key"

// stubKeys is a fake key provider registered under the AWS kind (any
// supported non-github-app kind will do).
type stubKeys struct {
	value []byte
	err   error
	calls atomic.Int32
}

func (s *stubKeys) Kind() string { return secretprovider.KindAWSSecretsManager }
func (s *stubKeys) ParseReference(raw string) (secretprovider.Reference, error) {
	return stubRef(raw), nil
}
func (s *stubKeys) Fetch(context.Context, secretprovider.Reference) (secretprovider.Result, error) {
	s.calls.Add(1)
	if s.err != nil {
		return secretprovider.Result{}, s.err
	}
	return secretprovider.NewResult(s.value, "v1")
}

type stubRef string

func (r stubRef) ProviderKind() string { return secretprovider.KindAWSSecretsManager }
func (r stubRef) Canonical() string    { return string(r) }

type fakeGitHub struct {
	t         *testing.T
	pub       *rsa.PublicKey
	mu        sync.Mutex
	mints     int
	status    int
	expiresIn time.Duration
	lastPath  string
	lastJWT   string
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastPath = r.Method + " " + r.URL.Path
	g.lastJWT = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if g.status != 0 {
		w.WriteHeader(g.status)
		_, _ = w.Write([]byte(`{"message":"ghs_SHOULD_NOT_LEAK"}`))
		return
	}
	g.mints++
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token":      "ghs_token_" + string(rune('0'+g.mints)),
		"expires_at": time.Now().Add(g.expiresIn).UTC().Format(time.RFC3339),
	})
}

type fixture struct {
	provider *Provider
	gh       *fakeGitHub
	keys     *stubKeys
	registry *secretprovider.Registry
	clock    *time.Time
}

func newFixture(t *testing.T, pkcs8 bool) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	gh := &fakeGitHub{t: t, pub: &key.PublicKey, expiresIn: time.Hour}
	server := httptest.NewTLSServer(gh)
	t.Cleanup(server.Close)
	keys := &stubKeys{value: pem.EncodeToMemory(block)}
	registry := secretprovider.NewRegistry()
	if err := registry.Register("onepassword", keys); err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	provider, err := New(Options{
		AppID: "2954702", InstallationID: "112589902", APIURL: server.URL,
		PrivateKeyProvider: "onepassword", PrivateKeyRef: keyRef, Keys: registry,
		HTTPClient: server.Client(), Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("axel", provider); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	return &fixture{provider: provider, gh: gh, keys: keys, registry: registry, clock: &clock}
}

func (f *fixture) fetch(t *testing.T, ref string) string {
	t.Helper()
	result, err := f.registry.Fetch(context.Background(), "axel", ref)
	if err != nil {
		t.Fatalf("fetch %q: %v", ref, err)
	}
	defer result.Wipe()
	return string(result.Bytes())
}

func TestMintsSignedJWTForInstallation(t *testing.T) {
	for _, pkcs8 := range []bool{false, true} {
		f := newFixture(t, pkcs8)
		if got := f.fetch(t, "token"); got != "ghs_token_1" {
			t.Fatalf("token = %q", got)
		}
		if f.gh.lastPath != "POST /app/installations/112589902/access_tokens" {
			t.Fatalf("request = %q", f.gh.lastPath)
		}
		parts := strings.Split(f.gh.lastJWT, ".")
		if len(parts) != 3 {
			t.Fatalf("jwt = %q", f.gh.lastJWT)
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(f.gh.pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("signature does not verify (pkcs8=%v): %v", pkcs8, err)
		}
		var header map[string]string
		var claims struct {
			Iat, Exp int64
			Iss      string
		}
		decode(t, parts[0], &header)
		decode(t, parts[1], &claims)
		if header["alg"] != "RS256" || header["typ"] != "JWT" {
			t.Fatalf("header = %v", header)
		}
		now := f.clock.Unix()
		if claims.Iss != "2954702" || claims.Iat != now-60 || claims.Exp != now+540 {
			t.Fatalf("claims = %+v (now %d)", claims, now)
		}
	}
}

func decode(t *testing.T, segment string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || json.Unmarshal(raw, into) != nil {
		t.Fatalf("bad segment %q: %v", segment, err)
	}
}

func TestTokenCachedSharedAndRemintedNearExpiry(t *testing.T) {
	f := newFixture(t, false)
	first, second := f.fetch(t, "token"), f.fetch(t, "token")
	if first != "ghs_token_1" || second != "ghs_token_1" {
		t.Fatal("token was not reused")
	}
	basic := f.fetch(t, "basic")
	want := base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_token_1"))
	if basic != want {
		t.Fatalf("basic = %q, want %q", basic, want)
	}
	if f.gh.mints != 1 || f.keys.calls.Load() != 1 {
		t.Fatalf("mints = %d, key reads = %d, want 1 and 1", f.gh.mints, f.keys.calls.Load())
	}

	// 49 minutes in: still more than 10 minutes left, so still cached.
	*f.clock = f.clock.Add(49 * time.Minute)
	if f.fetch(t, "token") != "ghs_token_1" {
		t.Fatal("token re-minted too early")
	}
	// 51 minutes in: inside the 10 minute margin, so re-mint and re-read the key.
	*f.clock = f.clock.Add(2 * time.Minute)
	if got := f.fetch(t, "token"); got != "ghs_token_2" {
		t.Fatalf("token after margin = %q", got)
	}
	if f.gh.mints != 2 || f.keys.calls.Load() != 2 {
		t.Fatalf("mints = %d, key reads = %d, want 2 and 2", f.gh.mints, f.keys.calls.Load())
	}
}

func TestVersionTracksExpiry(t *testing.T) {
	f := newFixture(t, false)
	ref, err := f.registry.Parse("axel", "token")
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.registry.FetchReference(context.Background(), "axel", ref)
	if err != nil || a.Version() == "" {
		t.Fatalf("version = %q, %v", a.Version(), err)
	}
	b, _ := f.registry.FetchReference(context.Background(), "axel", ref)
	if a.Version() != b.Version() {
		t.Fatalf("version changed without a re-mint: %q vs %q", a.Version(), b.Version())
	}
}

func TestInvalidReferences(t *testing.T) {
	f := newFixture(t, false)
	for _, raw := range []string{"Token", "basic ", "token?permissions=contents:read", "key", "x"} {
		if _, err := f.registry.Fetch(context.Background(), "axel", raw); secretprovider.CodeOf(err) != secretprovider.CodeInvalidReference {
			t.Errorf("ref %q: err = %v, want invalid_reference", raw, err)
		}
	}
	if f.gh.mints != 0 {
		t.Fatal("invalid reference reached GitHub")
	}
}

func TestGitHubErrorsMapToProviderCodes(t *testing.T) {
	cases := map[int]secretprovider.ErrorCode{
		http.StatusUnauthorized:        secretprovider.CodeAccessDenied,
		http.StatusForbidden:           secretprovider.CodeAccessDenied,
		http.StatusNotFound:            secretprovider.CodeNotFound,
		http.StatusInternalServerError: secretprovider.CodeUnavailable,
	}
	for status, want := range cases {
		f := newFixture(t, false)
		f.gh.status = status
		_, err := f.registry.Fetch(context.Background(), "axel", "token")
		if got := secretprovider.CodeOf(err); got != want {
			t.Errorf("status %d: code = %q, want %q", status, got, want)
		}
		if err != nil && strings.Contains(err.Error(), "SHOULD_NOT_LEAK") {
			t.Errorf("status %d: upstream body leaked", status)
		}
	}
}

func TestMalformedGitHubResponseIsInvalidResponse(t *testing.T) {
	f := newFixture(t, false)
	f.gh.expiresIn = -time.Hour // already expired
	if _, err := f.registry.Fetch(context.Background(), "axel", "token"); secretprovider.CodeOf(err) != secretprovider.CodeInvalidResponse {
		t.Fatalf("err = %v, want invalid_response", err)
	}
}

func TestKeyProviderFailureFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want secretprovider.ErrorCode
	}{
		{"unavailable", secretprovider.NewError(secretprovider.CodeUnavailable), secretprovider.CodeUnavailable},
		{"denied", secretprovider.NewError(secretprovider.CodeAccessDenied), secretprovider.CodeAccessDenied},
		{"missing", secretprovider.NewError(secretprovider.CodeNotFound), secretprovider.CodeNotFound},
		{"key reference invalid is not our reference problem", secretprovider.NewError(secretprovider.CodeInvalidReference), secretprovider.CodeUnavailable},
		{"opaque error", errors.New("dial tcp 10.0.0.1: SECRET-DETAIL"), secretprovider.CodeUnavailable},
	}
	for _, tc := range cases {
		f := newFixture(t, false)
		f.keys.err = tc.err
		_, err := f.registry.Fetch(context.Background(), "axel", "token")
		if got := secretprovider.CodeOf(err); got != tc.want {
			t.Errorf("%s: code = %q, want %q", tc.name, got, tc.want)
		}
		if f.gh.mints != 0 {
			t.Errorf("%s: reached GitHub without a key", tc.name)
		}
	}
}

func TestBadKeyMaterialFailsClosed(t *testing.T) {
	f := newFixture(t, false)
	f.keys.value = []byte("not a pem")
	if _, err := f.registry.Fetch(context.Background(), "axel", "token"); secretprovider.CodeOf(err) != secretprovider.CodeInvalidResponse {
		t.Fatalf("err = %v, want invalid_response", err)
	}
}

func TestCachedTokenSurvivesKeyProviderOutage(t *testing.T) {
	f := newFixture(t, false)
	f.fetch(t, "token")
	f.keys.err = secretprovider.NewError(secretprovider.CodeUnavailable)
	if f.fetch(t, "token") != "ghs_token_1" {
		t.Fatal("cached token should not need the key provider")
	}
}

func TestNewValidation(t *testing.T) {
	good := Options{
		AppID: "1", InstallationID: "2", PrivateKeyProvider: "p", PrivateKeyRef: "r",
		Keys: secretprovider.NewRegistry(),
	}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Options){
		"empty app id":        func(o *Options) { o.AppID = "" },
		"non-numeric install": func(o *Options) { o.InstallationID = "abc" },
		"no key provider":     func(o *Options) { o.PrivateKeyProvider = "" },
		"no key ref":          func(o *Options) { o.PrivateKeyRef = "" },
		"no key source":       func(o *Options) { o.Keys = nil },
		"http api url":        func(o *Options) { o.APIURL = "http://api.github.com" },
		"api url creds":       func(o *Options) { o.APIURL = "https://u:p@api.github.com" },
	}
	for name, mutate := range mutations {
		o := good
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCancellationContract(t *testing.T) {
	f := newFixture(t, false)
	contracttest.RequireCancellation(t, f.provider, "token")
}
