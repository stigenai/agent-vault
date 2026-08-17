package openbaoauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

type fakeJWTSource struct {
	mu       sync.Mutex
	calls    int
	audience string
	svid     *jwtsvid.SVID
	err      error
}

func (f *fakeJWTSource) FetchJWTSVID(_ context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.audience = params.Audience
	return f.svid, f.err
}

func TestJWTTokenSourceFetchesAudienceBoundSVIDForEveryLogin(t *testing.T) {
	const audience = "https://openbao.example/v1/auth/jwt/login"
	svid := testJWTSVID(t, audience)
	var mu sync.Mutex
	logins := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body loginRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if request.URL.Path != "/v1/auth/spire/login" || body.Role != "agent-vault" || body.JWT != svid.Marshal() {
			t.Errorf("login = %s %#v", request.URL.Path, body)
		}
		mu.Lock()
		logins++
		current := logins
		mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"auth":{"client_token":"ephemeral-%d"}}`, current)
	}))
	defer server.Close()
	source := &fakeJWTSource{svid: svid}
	tokens, err := NewJWTTokenSource(JWTOptions{
		Address: server.URL, AuthMount: "spire", Role: "agent-vault",
		Audience: audience, Source: source, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := tokens.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := tokens.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != "ephemeral-1" || string(second) != "ephemeral-2" {
		t.Fatalf("tokens = %q, %q", first, second)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.calls != 2 || source.audience != audience {
		t.Fatalf("JWT fetches = %d, audience %q", source.calls, source.audience)
	}
}

func TestJWTTokenSourceSanitizesAuthenticationFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "SECRET-AUTH-DETAIL", http.StatusForbidden)
	}))
	defer server.Close()
	source := &fakeJWTSource{svid: testJWTSVID(t, "openbao")}
	tokens, err := NewJWTTokenSource(JWTOptions{
		Address: server.URL, Role: "agent-vault", Audience: "openbao",
		Source: source, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Token(context.Background()); err != ErrDenied {
		t.Fatalf("error = %v", err)
	}
}

func testJWTSVID(t *testing.T, audience string) *jwtsvid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  "spiffe://cluster.example/ns/agents/sa/agent-vault",
		Audience: josejwt.Audience{audience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	svid, err := jwtsvid.ParseInsecure(token, []string{audience})
	if err != nil {
		t.Fatal(err)
	}
	return svid
}
