package cmd

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauth"
)

func TestAdminBridgeForwardsOnlySPIFFEIdentityAndSafeOAuthOrigin(t *testing.T) {
	t.Parallel()

	type observedRequest struct {
		path    string
		query   string
		headers http.Header
	}
	observed := make(chan observedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- observedRequest{path: r.URL.Path, query: r.URL.RawQuery, headers: r.Header.Clone()}
		w.Header().Set("Set-Cookie", "av_session=must-not-reach-browser")
		w.Header().Set("Server", "upstream-detail")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	var audit bytes.Buffer
	handler := newAdminBridgeHandler(target, http.DefaultTransport, defaultAdminBridgeOrigin, nil, func(event string) {
		audit.WriteString(event + "\n")
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/connect?state=browser-secret", strings.NewReader(`{"client_secret":"body-secret"}`))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Host = "127.0.0.1:19443"
	req.Header.Set("Origin", defaultAdminBridgeOrigin)
	req.Header.Set("Authorization", "Bearer browser-secret")
	req.Header.Set("Cookie", "av_session=browser-secret")
	req.Header.Set("Proxy-Authorization", "Basic browser-secret")
	req.Header.Set("Forwarded", "for=203.0.113.10")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Set("X-SPIFFE-ID", "spiffe://attacker.example/workload")
	req.Header.Set(oauth.LoopbackRedirectOriginHeader, "http://attacker.example:19443")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := <-observed
	if got.path != "/v1/credentials/oauth/connect" || got.query != "state=browser-secret" {
		t.Fatalf("upstream target = %s?%s", got.path, got.query)
	}
	for _, header := range []string{
		"Authorization", "Cookie", "Proxy-Authorization", "Forwarded",
		"X-Forwarded-For", "X-Real-IP", "X-SPIFFE-ID",
	} {
		if value := got.headers.Get(header); value != "" {
			t.Fatalf("%s forwarded as %q", header, value)
		}
	}
	if origin := got.headers.Get(oauth.LoopbackRedirectOriginHeader); origin != defaultAdminBridgeOrigin {
		t.Fatalf("OAuth loopback origin = %q, want %q", origin, defaultAdminBridgeOrigin)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("upstream cookies reached browser: %#v", cookies)
	}
	if server := rec.Header().Get("Server"); server != "" {
		t.Fatalf("upstream Server header reached browser: %q", server)
	}
	logText := audit.String()
	for _, secret := range []string{"browser-secret", "body-secret", "attacker.example", "203.0.113.10"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("audit output leaked %q: %s", secret, logText)
		}
	}
	if !strings.Contains(logText, "method=POST route=oauth_connect") {
		t.Fatalf("missing value-safe audit event: %s", logText)
	}
}

func TestAdminBridgeCallbackForwardsQueryWithoutAuditingValues(t *testing.T) {
	t.Parallel()

	query := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query <- r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	var audit bytes.Buffer
	handler := newAdminBridgeHandler(target, http.DefaultTransport, defaultAdminBridgeOrigin, nil, func(event string) {
		audit.WriteString(event)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/oauth/callback?code=oauth-code-secret&state=oauth-state-secret", nil)
	req.RemoteAddr = "[::1]:54321"
	req.Host = "127.0.0.1:19443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := <-query; got != "code=oauth-code-secret&state=oauth-state-secret" {
		t.Fatalf("callback query = %q", got)
	}
	if strings.Contains(audit.String(), "oauth-code-secret") || strings.Contains(audit.String(), "oauth-state-secret") {
		t.Fatalf("callback values leaked to audit: %s", audit.String())
	}
	if !strings.Contains(audit.String(), "route=oauth_callback") {
		t.Fatalf("missing callback audit class: %s", audit.String())
	}
}

func TestAdminBridgeRejectsNonLoopbackClient(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	transport := adminBridgeRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not be called")
	})
	target, _ := url.Parse("https://agent-vault.example")
	handler := newAdminBridgeHandler(target, transport, defaultAdminBridgeOrigin, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Host = "127.0.0.1:19443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("non-loopback response=%d upstream_calls=%d", rec.Code, calls.Load())
	}
}

func TestAdminBridgeHealthAndReadinessAreLocalAndValueSafe(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	transport := adminBridgeRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not be called")
	})
	target, _ := url.Parse("https://agent-vault.example")
	handler := newAdminBridgeHandler(target, transport, defaultAdminBridgeOrigin, func() error {
		return errors.New("SPIFFE socket /secret/path is unavailable")
	}, nil)

	for path, want := range map[string]int{"/healthz": http.StatusNoContent, "/readyz": http.StatusServiceUnavailable} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Host = "127.0.0.1:19443"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Result().Body)
		if rec.Code != want || strings.Contains(string(body), "/secret/path") {
			t.Fatalf("%s response=%d body=%q", path, rec.Code, body)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("local probes made %d upstream calls", calls.Load())
	}
}

func TestAdminBridgeUpstreamErrorDoesNotLeakTransportDetails(t *testing.T) {
	t.Parallel()

	transport := adminBridgeRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp database-token-secret@10.0.0.1")
	})
	target, _ := url.Parse("https://agent-vault.example")
	var audit bytes.Buffer
	handler := newAdminBridgeHandler(target, transport, defaultAdminBridgeOrigin, nil, func(event string) {
		audit.WriteString(event)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Host = "127.0.0.1:19443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	combined := rec.Body.String() + audit.String()
	if rec.Code != http.StatusBadGateway || strings.Contains(combined, "database-token-secret") || strings.Contains(combined, "10.0.0.1") {
		t.Fatalf("unsafe upstream error response=%d output=%q", rec.Code, combined)
	}
}

func TestAdminBridgeRejectsDNSRebindingAndCrossOriginRequests(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	transport := adminBridgeRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not be called")
	})
	target, _ := url.Parse("https://agent-vault.example")
	handler := newAdminBridgeHandler(target, transport, defaultAdminBridgeOrigin, nil, nil)

	for _, tc := range []struct {
		name   string
		host   string
		origin string
	}{
		{name: "rebinding host", host: "attacker.example:19443"},
		{name: "cross origin", host: "127.0.0.1:19443", origin: "https://attacker.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(`{"credential":"secret"}`))
			req.RemoteAddr = "127.0.0.1:54321"
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("unsafe requests made %d upstream calls", calls.Load())
	}
}

func TestValidateAdminBridgeListenAddress(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"127.0.0.1:19443", "[::1]:19443"} {
		if err := validateAdminBridgeListenAddress(address); err != nil {
			t.Errorf("valid address %q: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:19443", "localhost:19443", "10.0.0.1:19443", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http"} {
		if err := validateAdminBridgeListenAddress(address); err == nil {
			t.Errorf("unsafe address %q accepted", address)
		}
	}
}

type adminBridgeRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f adminBridgeRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
