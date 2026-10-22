package spiffejwtsvid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/contracttest"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testRef = "spiffe://example.org/agent/read?audience=kubernetes"

type fakeSource struct {
	mu     sync.Mutex
	now    func() time.Time
	ttl    time.Duration
	err    error
	calls  []jwtsvid.Params
	serial int
}

func (f *fakeSource) FetchJWTSVID(_ context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, params)
	if f.err != nil {
		return nil, f.err
	}
	f.serial++
	exp := f.now().Add(f.ttl)
	signed := unsignedJWT(map[string]any{
		"sub": params.Subject.String(), "aud": []string{params.Audience}, "exp": exp.Unix(), "jti": strconv.Itoa(f.serial),
	})
	// Parse without verification to build an SVID the way the client would.
	svid, err := jwtsvid.ParseInsecure(signed, []string{params.Audience})
	return svid, err
}

// unsignedJWT builds a structurally valid JWT; ParseInsecure does not check
// the signature.
func unsignedJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k"})
	body, _ := json.Marshal(claims)
	return enc.EncodeToString(header) + "." + enc.EncodeToString(body) + "." + enc.EncodeToString([]byte("sig"))
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(t *testing.T, ttl time.Duration) (*Provider, *fakeSource, *clock) {
	t.Helper()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	src := &fakeSource{now: c.now, ttl: ttl}
	p, err := New(context.Background(), Options{Source: src, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return p, src, c
}

func fetch(t *testing.T, p *Provider, raw string) secretprovider.Result {
	t.Helper()
	ref, err := p.ParseReference(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	return res
}

func TestParseReferenceCanonicalizesAndRejects(t *testing.T) {
	p, _, _ := newTest(t, 5*time.Minute)
	ref, err := p.ParseReference("spiffe://example.org/agent/read?audience=kubernetes&audience=other")
	if err != nil {
		t.Fatal(err)
	}
	if got := ref.Canonical(); got != "spiffe://example.org/agent/read?audience=kubernetes&audience=other" {
		t.Fatalf("canonical = %q", got)
	}
	for _, raw := range []string{
		"", "spiffe://example.org/agent/read", "spiffe://example.org/agent/read?audience=",
		"spiffe://example.org?audience=x", "https://example.org/a?audience=x",
		"spiffe://example.org/a?audience=x&other=y", "spiffe://example.org/a?audience=x#frag",
		"spiffe://example.org/a?aud=x", "spiffe://example.org/a?audience=%0a",
	} {
		if _, err := p.ParseReference(raw); secretprovider.CodeOf(err) != secretprovider.CodeInvalidReference {
			t.Fatalf("reference %q error = %v", raw, err)
		}
	}
}

func TestFetchPassesSubjectAndAudiencesAndCaches(t *testing.T) {
	p, src, _ := newTest(t, 5*time.Minute)
	first := fetch(t, p, "spiffe://example.org/agent/read?audience=kubernetes&audience=extra")
	defer first.Wipe()
	if !strings.HasPrefix(string(first.Bytes()), "eyJ") || first.Version() == "" {
		t.Fatal("result is not a JWT with a version")
	}
	call := src.calls[0]
	if call.Subject != spiffeid.RequireFromString("spiffe://example.org/agent/read") ||
		call.Audience != "kubernetes" || len(call.ExtraAudiences) != 1 || call.ExtraAudiences[0] != "extra" {
		t.Fatalf("params = %#v", call)
	}
	second := fetch(t, p, "spiffe://example.org/agent/read?audience=kubernetes&audience=extra")
	defer second.Wipe()
	if len(src.calls) != 1 || string(second.Bytes()) != string(first.Bytes()) {
		t.Fatalf("cache hit made %d calls", len(src.calls))
	}
	other := fetch(t, p, "spiffe://example.org/agent/write?audience=kubernetes")
	defer other.Wipe()
	if len(src.calls) != 2 {
		t.Fatalf("distinct subject must not share cache; calls = %d", len(src.calls))
	}
}

func TestFetchRefreshesNearExpiryAndKeepsMinimumLifetime(t *testing.T) {
	p, src, c := newTest(t, 5*time.Minute)
	first := fetch(t, p, testRef)
	defer first.Wipe()
	// Just before the one-third mark: still cached.
	c.t = c.t.Add(3*time.Minute + 10*time.Second)
	cached := fetch(t, p, testRef)
	defer cached.Wipe()
	if len(src.calls) != 1 {
		t.Fatalf("refetched too early: %d calls", len(src.calls))
	}
	// Past it (less than 100s left): refetch.
	c.t = c.t.Add(30 * time.Second)
	renewed := fetch(t, p, testRef)
	defer renewed.Wipe()
	if len(src.calls) != 2 || string(renewed.Bytes()) == string(first.Bytes()) {
		t.Fatalf("expected a renewed token, calls = %d", len(src.calls))
	}
}

func TestFetchRejectsTokenWithTooLittleLifetime(t *testing.T) {
	p, _, _ := newTest(t, 30*time.Second)
	ref, _ := p.ParseReference(testRef)
	if _, err := p.Fetch(context.Background(), ref); secretprovider.CodeOf(err) != secretprovider.CodeUnavailable {
		t.Fatalf("short-lived token error = %v", err)
	}
}

func TestFetchMapsWorkloadAPIErrors(t *testing.T) {
	tests := map[string]struct {
		err  error
		code secretprovider.ErrorCode
	}{
		"unavailable":  {status.Error(codes.Unavailable, "dial unix /run/x: connection refused"), secretprovider.CodeUnavailable},
		"not issued":   {status.Error(codes.PermissionDenied, "no identity issued"), secretprovider.CodeAccessDenied},
		"unknown":      {status.Error(codes.NotFound, "x"), secretprovider.CodeNotFound},
		"bad audience": {status.Error(codes.InvalidArgument, "x"), secretprovider.CodeInvalidReference},
		"plain error":  {errors.New("secret-token-text"), secretprovider.CodeUnavailable},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, src, _ := newTest(t, 5*time.Minute)
			src.err = tc.err
			ref, _ := p.ParseReference(testRef)
			_, err := p.Fetch(context.Background(), ref)
			if secretprovider.CodeOf(err) != tc.code {
				t.Fatalf("code = %s, want %s", secretprovider.CodeOf(err), tc.code)
			}
			if strings.Contains(err.Error(), "secret-token-text") || strings.Contains(err.Error(), "/run/x") {
				t.Fatalf("error leaks upstream detail: %v", err)
			}
		})
	}
}

func TestCloseWipesCache(t *testing.T) {
	p, _, _ := newTest(t, 5*time.Minute)
	res := fetch(t, p, testRef)
	res.Wipe()
	if err := p.Close(); err != nil || len(p.cache) != 0 {
		t.Fatalf("close = %v, cache = %d", err, len(p.cache))
	}
}

func TestProviderContract(t *testing.T) {
	p, _, _ := newTest(t, 5*time.Minute)
	contracttest.RequireCancellation(t, p, testRef)
}
