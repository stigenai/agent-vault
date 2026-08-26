package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

const (
	defaultAdminBridgeListen       = "127.0.0.1:19443"
	defaultAdminBridgeOrigin       = "http://127.0.0.1:19443"
	adminBridgeCapabilityParam     = "av_owner_capability"
	adminBridgeSessionCookie       = "agent_vault_owner_bridge"
	adminBridgeCapabilityTTL       = 10 * time.Minute
	adminBridgeSessionTTL          = 30 * time.Minute
	adminBridgeCapabilityByteCount = 32
)

var adminBridgeCmd = &cobra.Command{
	Use:   "bridge",
	Short: "Run the loopback-only SPIFFE human-admin bridge",
	Args:  cobra.NoArgs,
	RunE:  runAdminBridgeCommand,
}

func runAdminBridgeCommand(cmd *cobra.Command, _ []string) error {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}
	listenAddress, err := cmd.Flags().GetString("listen")
	if err != nil {
		return err
	}
	publicOrigin, err := cmd.Flags().GetString("public-origin")
	if err != nil {
		return err
	}
	serverSPIFFEID, err := cmd.Flags().GetString("server-spiffe-id")
	if err != nil {
		return err
	}
	if err := validateAdminBridgeListenAddress(listenAddress); err != nil {
		return err
	}
	if _, err := oauth.LoopbackCallbackURL(publicOrigin); err != nil {
		return fmt.Errorf("invalid --public-origin: %w", err)
	}

	client, err := runtimeconfig.LoadClient(runtimeconfig.ClientOptions{Path: configPath})
	if err != nil {
		return fmt.Errorf("load admin bridge client configuration: %w", err)
	}
	if client.WorkloadAPI == "" {
		return fmt.Errorf("admin bridge requires client.workload_api and a SPIFFE X.509-SVID")
	}
	target, err := url.Parse(client.Address)
	if err != nil || target.Scheme != "https" || target.Host == "" || (target.Path != "" && target.Path != "/") {
		return fmt.Errorf("client.address must be an HTTPS origin without a path")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	source, transport, err := newAdminBridgeSPIFFETransport(ctx, client, serverSPIFFEID)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	capabilityGate, bootstrapCapability, err := newAdminBridgeCapabilityGate(time.Now)
	if err != nil {
		return fmt.Errorf("generate admin bridge owner capability: %w", err)
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for admin bridge: %w", err)
	}
	defer func() { _ = listener.Close() }()

	audit := func(event string) {
		fmt.Fprintf(cmd.ErrOrStderr(), "agent-vault: admin bridge %s\n", event)
	}
	handler := newAdminBridgeHandler(target, transport, publicOrigin, capabilityGate, source.Ready, audit)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(cmd.ErrOrStderr(), "agent-vault: admin bridge server: ", 0),
	}

	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	audit("started; access requires a Kubernetes port-forward and one-time owner capability")
	_, _ = fmt.Fprintf(
		cmd.OutOrStdout(),
		"Open this one-time admin URL within 10 minutes: %s/?%s=%s\n",
		strings.TrimSuffix(publicOrigin, "/"),
		adminBridgeCapabilityParam,
		bootstrapCapability,
	)
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("serve admin bridge: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		audit("stopping")
		return server.Shutdown(shutdownCtx)
	}
}

func newAdminBridgeSPIFFETransport(ctx context.Context, client runtimeconfig.Client, rawServerID string) (*workloadidentity.Source, http.RoundTripper, error) {
	serverID, err := validateAdminBridgeServerID(rawServerID, client.TrustDomains)
	if err != nil {
		return nil, nil, err
	}
	source, err := workloadidentity.New(ctx, workloadidentity.Options{Address: client.WorkloadAPI})
	if err != nil {
		return nil, nil, fmt.Errorf("connect admin bridge to SPIRE Workload API: %w", err)
	}
	tlsConfig, err := source.ClientTLSConfig(tlsconfig.AuthorizeID(serverID))
	if err != nil {
		_ = source.Close()
		return nil, nil, fmt.Errorf("configure admin bridge SPIFFE mTLS: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	return source, &clientHeaderTransport{base: &spiffeRoundTripper{base: transport}}, nil
}

func validateAdminBridgeServerID(rawServerID string, trustDomains []string) (spiffeid.ID, error) {
	serverID, err := spiffeid.FromString(rawServerID)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid --server-spiffe-id: %w", err)
	}
	serverTrustDomainConfigured := false
	for _, raw := range trustDomains {
		domain, err := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
		if err != nil {
			return spiffeid.ID{}, fmt.Errorf("invalid admin bridge SPIFFE trust domain %q: %w", raw, err)
		}
		if domain == serverID.TrustDomain() {
			serverTrustDomainConfigured = true
		}
	}
	if !serverTrustDomainConfigured {
		return spiffeid.ID{}, fmt.Errorf("--server-spiffe-id trust domain is not configured in client.trust_domains")
	}
	return serverID, nil
}

type adminBridgeCapabilityGate struct {
	mu            sync.Mutex
	bootstrapHash [sha256.Size]byte
	sessionHash   [sha256.Size]byte
	expiresAt     time.Time
	sessionExpiry time.Time
	consumed      bool
	now           func() time.Time
}

func newAdminBridgeCapabilityGate(now func() time.Time) (*adminBridgeCapabilityGate, string, error) {
	if now == nil {
		now = time.Now
	}
	bootstrap, err := randomAdminBridgeToken()
	if err != nil {
		return nil, "", err
	}
	return &adminBridgeCapabilityGate{
		bootstrapHash: sha256.Sum256([]byte(bootstrap)),
		expiresAt:     now().Add(adminBridgeCapabilityTTL),
		now:           now,
	}, bootstrap, nil
}

func randomAdminBridgeToken() (string, error) {
	raw := make([]byte, adminBridgeCapabilityByteCount)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (g *adminBridgeCapabilityGate) bootstrap(rawCapability string) (string, time.Time, bool, error) {
	if g == nil || rawCapability == "" {
		return "", time.Time{}, false, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.consumed || !g.now().Before(g.expiresAt) {
		return "", time.Time{}, false, nil
	}
	candidate := sha256.Sum256([]byte(rawCapability))
	if subtle.ConstantTimeCompare(candidate[:], g.bootstrapHash[:]) != 1 {
		return "", time.Time{}, false, nil
	}
	session, err := randomAdminBridgeToken()
	if err != nil {
		return "", time.Time{}, false, err
	}
	g.sessionHash = sha256.Sum256([]byte(session))
	g.sessionExpiry = g.now().Add(adminBridgeSessionTTL)
	g.bootstrapHash = [sha256.Size]byte{}
	g.consumed = true
	return session, g.sessionExpiry, true, nil
}

func (g *adminBridgeCapabilityGate) authorized(rawSession string) bool {
	if g == nil || rawSession == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.consumed || !g.now().Before(g.sessionExpiry) {
		return false
	}
	candidate := sha256.Sum256([]byte(rawSession))
	return subtle.ConstantTimeCompare(candidate[:], g.sessionHash[:]) == 1
}

func newAdminBridgeHandler(target *url.URL, transport http.RoundTripper, publicOrigin string, capabilityGate *adminBridgeCapabilityGate, ready func() error, audit func(string)) http.Handler {
	publicOriginURL, _ := url.Parse(publicOrigin)
	publicHost := publicOriginURL.Host
	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host
		for _, header := range []string{
			"Authorization", "Cookie", "Forwarded", "Proxy-Authorization",
			"X-Forwarded-Host", "X-Forwarded-Proto",
			"X-Real-IP", "X-SPIFFE-ID", oauth.LoopbackRedirectOriginHeader,
		} {
			req.Header.Del(header)
		}
		// A nil slice is the documented ReverseProxy sentinel that prevents
		// ServeHTTP from appending the local port-forward address.
		req.Header["X-Forwarded-For"] = nil
		req.Header.Set(oauth.LoopbackRedirectOriginHeader, publicOrigin)
	}
	proxy.Transport = transport
	proxy.ErrorLog = log.New(noopWriter{}, "", 0)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		if audit != nil {
			audit("upstream request failed")
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "Agent Vault is temporarily unavailable", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Set-Cookie")
		resp.Header.Del("Server")
		resp.Header.Set("Cache-Control", "no-store")
		if location := resp.Header.Get("Location"); location != "" {
			if parsed, err := url.Parse(location); err == nil && parsed.Scheme == target.Scheme && parsed.Host == target.Host {
				resp.Header.Set("Location", publicOrigin+parsed.RequestURI())
			}
		}
		return nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !isLoopbackRemoteAddress(r.RemoteAddr) {
			http.Error(w, "admin bridge accepts loopback clients only", http.StatusForbidden)
			return
		}
		origins := r.Header.Values("Origin")
		if publicHost == "" || r.Host != publicHost || len(origins) > 1 || (len(origins) == 1 && origins[0] != publicOrigin) {
			http.Error(w, "admin bridge requires the configured loopback origin", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/readyz":
			if ready != nil && ready() != nil {
				http.Error(w, "workload identity unavailable", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if values, present := r.URL.Query()[adminBridgeCapabilityParam]; present {
			if r.Method != http.MethodGet || r.URL.Path != "/" || len(r.URL.Query()) != 1 || len(values) != 1 {
				http.Error(w, "invalid owner capability bootstrap request", http.StatusBadRequest)
				return
			}
			session, expiresAt, ok, err := capabilityGate.bootstrap(values[0])
			if err != nil {
				http.Error(w, "owner capability unavailable", http.StatusServiceUnavailable)
				return
			}
			if !ok {
				http.Error(w, "owner capability invalid or expired", http.StatusUnauthorized)
				return
			}
			// #nosec G124 -- OAuth native-app loopback redirects intentionally use
			// HTTP. Host-only, HttpOnly, SameSite=Lax, short lifetime, exact
			// Host/Origin checks, and the in-memory capability gate are the boundary.
			http.SetCookie(w, &http.Cookie{
				Name:     adminBridgeSessionCookie,
				Value:    session,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(adminBridgeSessionTTL.Seconds()),
				Expires:  expiresAt,
			})
			if audit != nil {
				audit("owner capability consumed")
			}
			http.Redirect(w, r, strings.TrimSuffix(publicOrigin, "/")+"/", http.StatusSeeOther)
			return
		}
		cookies := r.CookiesNamed(adminBridgeSessionCookie)
		if len(cookies) != 1 || !capabilityGate.authorized(cookies[0].Value) {
			http.Error(w, "owner capability required", http.StatusUnauthorized)
			return
		}
		if audit != nil {
			audit("request method=" + r.Method + " route=" + adminBridgeRouteClass(r.URL.Path))
		}
		proxy.ServeHTTP(w, r)
	})
}

func validateAdminBridgeListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid --listen: %w", err)
	}
	if host != "127.0.0.1" && host != "::1" {
		return fmt.Errorf("--listen must use the exact loopback address 127.0.0.1 or ::1")
	}
	if port == "" || port == "0" {
		return fmt.Errorf("--listen must use an explicit non-zero port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("--listen port must be between 1 and 65535")
	}
	return nil
}

func isLoopbackRemoteAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func adminBridgeRouteClass(path string) string {
	switch path {
	case "/v1/credentials/oauth/connect":
		return "oauth_connect"
	case "/v1/oauth/callback":
		return "oauth_callback"
	default:
		if strings.HasPrefix(path, "/v1/") {
			return "api"
		}
		return "ui"
	}
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

func init() {
	adminBridgeCmd.Flags().String("config", "", "path to versioned TOML containing the public [client] configuration")
	adminBridgeCmd.Flags().String("listen", defaultAdminBridgeListen, "loopback listen address used inside the admin bridge pod")
	adminBridgeCmd.Flags().String("public-origin", defaultAdminBridgeOrigin, "exact browser loopback origin used by the Kubernetes port-forward")
	adminBridgeCmd.Flags().String("server-spiffe-id", "", "exact Agent Vault server SPIFFE ID required for upstream mTLS")
	_ = adminBridgeCmd.MarkFlagRequired("server-spiffe-id")
	ownerCmd.AddCommand(adminBridgeCmd)
}
