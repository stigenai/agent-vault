package oauth

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// LoopbackRedirectOriginHeader is set by the SVID-authenticated admin bridge
// when a browser starts an OAuth authorization-code flow. The server must not
// trust this header from ordinary clients; it is only an input to the
// SPIFFE-owner authorization performed by the server handler.
const LoopbackRedirectOriginHeader = "X-Agent-Vault-OAuth-Redirect-Origin"

const oauthCallbackPath = "/v1/oauth/callback"

// LoopbackCallbackURL validates a browser origin and returns the exact OAuth
// callback URL. Only explicit-port HTTP loopback origins are accepted. OAuth
// native-app loopback redirects intentionally use HTTP because the traffic
// never leaves the local host (and, for the admin bridge, is carried through a
// Kubernetes port-forward).
func LoopbackCallbackURL(rawOrigin string) (string, error) {
	u, err := url.Parse(rawOrigin)
	if err != nil {
		return "", fmt.Errorf("parse loopback origin: %w", err)
	}
	if u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" {
		return "", fmt.Errorf("origin must be an http:// loopback origin without userinfo, path, query, or fragment")
	}
	if !isLoopbackHostname(u.Hostname()) {
		return "", fmt.Errorf("origin host must be 127.0.0.1, ::1, or localhost")
	}
	port := u.Port()
	if port == "" {
		return "", fmt.Errorf("origin must include an explicit port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("origin port must be between 1 and 65535")
	}
	if u.Host != net.JoinHostPort(u.Hostname(), port) {
		return "", fmt.Errorf("origin host must be canonical")
	}
	return rawOrigin + oauthCallbackPath, nil
}

// LoopbackOriginFromCallbackURL validates an exact callback URL previously
// produced by LoopbackCallbackURL and returns its origin. This second check
// prevents a corrupted database row from becoming an open redirect.
func LoopbackOriginFromCallbackURL(rawCallback string) (string, error) {
	u, err := url.Parse(rawCallback)
	if err != nil || u.Path != oauthCallbackPath || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid loopback callback URL")
	}
	u.Path = ""
	origin := u.String()
	callback, err := LoopbackCallbackURL(origin)
	if err != nil || callback != rawCallback {
		return "", fmt.Errorf("invalid loopback callback URL")
	}
	return origin, nil
}

func isLoopbackHostname(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}
