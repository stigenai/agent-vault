package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

func TestNewWithRuntimeDoesNotReReadTrustedProxyOrRateLimitEnvironment(t *testing.T) {
	t.Setenv("AGENT_VAULT_TRUSTED_PROXIES", "127.0.0.0/8")
	t.Setenv("AGENT_VAULT_RATELIMIT_PROFILE", "loose")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	s := NewWithRuntime("127.0.0.1:0", nil, make([]byte, 32), nil, true, "http://127.0.0.1", logger, RuntimeOptions{
		RateLimit: ratelimit.DefaultsFor(ratelimit.ProfileStrict),
	})
	r := &http.Request{RemoteAddr: "127.0.0.1:1234", Header: http.Header{"X-Forwarded-For": []string{"203.0.113.8"}}}
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("unconfigured trusted proxy accepted XFF: %q", got)
	}
	if got := s.RateLimit().Config().Profile; got != ratelimit.ProfileStrict {
		t.Fatalf("rate-limit profile = %q, want strict", got)
	}

	_, trusted, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s = NewWithRuntime("127.0.0.1:0", nil, make([]byte, 32), nil, true, "http://127.0.0.1", logger, RuntimeOptions{
		RateLimit:      ratelimit.DefaultsFor(ratelimit.ProfileStrict),
		TrustedProxies: []net.IPNet{*trusted},
	})
	if got := s.clientIP(r); got != "203.0.113.8" {
		t.Fatalf("configured trusted proxy ignored XFF: %q", got)
	}
}
