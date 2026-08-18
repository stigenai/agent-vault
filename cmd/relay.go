package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/observability"
	localrelay "github.com/Infisical/agent-vault/internal/relay"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Run the SPIFFE proxy relay",
	Args:  cobra.NoArgs,
	RunE:  runRelayCommand,
}

func runRelayCommand(cmd *cobra.Command, _ []string) error {
	cfg, err := loadRelayConfig(cmd)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	source, err := workloadidentity.New(ctx, workloadidentity.Options{Address: cfg.Client.WorkloadAPI})
	if err != nil {
		return fmt.Errorf("start relay workload identity: %w", err)
	}
	defer source.Close()
	domains, err := relayTrustDomains(cfg.Client.TrustDomains)
	if err != nil {
		return err
	}
	dial, err := localrelay.NewSPIFFEDialContext(localrelay.SPIFFEDialOptions{Source: source, TrustDomains: domains})
	if err != nil {
		return err
	}
	metrics := observability.New()
	var metricsDone <-chan error
	stopMetrics := func(context.Context) error { return nil }
	if cfg.Relay.MetricsAddress != "" {
		metricsTLS, tlsErr := source.ServerTLSConfig(workloadidentity.AuthorizeTrustDomains(domains...))
		if tlsErr != nil {
			return fmt.Errorf("configure relay metrics mTLS: %w", tlsErr)
		}
		metricsDone, stopMetrics, err = startRelayMetrics(cfg.Relay.MetricsAddress, metricsTLS, metrics, source)
		if err != nil {
			return err
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = stopMetrics(shutdownCtx)
		}()
	}
	r, err := localrelay.New(localrelay.Options{
		RemoteAddr:           cfg.Relay.RemoteAddress,
		DialContext:          dial,
		AllowNetworkListener: cfg.Relay.ListenerMode == "network",
		OnDialResult: func(success bool) {
			metrics.RecordRelayDial(success)
			if success {
				slog.Debug("relay central connection established", "event", "relay_connectivity", "outcome", "connected")
			} else {
				slog.Warn("relay central connection failed", "event", "relay_connectivity", "outcome", "dial_failed")
			}
		},
		OnConnection: metrics.AddRelayConnection,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Relay.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for local relay clients: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Serve(listener) }()
	fmt.Fprintf(cmd.ErrOrStderr(), "%s relay listening on %s\n", successText("agent-vault:"), listener.Addr())
	select {
	case err := <-done:
		return err
	case err := <-metricsDone:
		if err != nil {
			return fmt.Errorf("relay metrics server: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return r.Shutdown(shutdownCtx)
	}
}

func startRelayMetrics(address string, tlsConfig *tls.Config, metrics *observability.Registry, source *workloadidentity.Source) (<-chan error, func(context.Context) error, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for relay metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now().UTC()
		snapshot := observability.RelaySnapshot{}
		if source.Ready() == nil {
			snapshot.SPIFFEUp = true
			snapshot.SVIDExpiresAt, _ = source.ExpiresAt()
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = metrics.WriteRelay(w, snapshot, now)
	})
	server := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		err := server.ServeTLS(listener, "", "")
		if err == http.ErrServerClosed {
			err = nil
		}
		done <- err
	}()
	return done, server.Shutdown, nil
}

func loadRelayConfig(cmd *cobra.Command) (runtimeconfig.RelayClient, error) {
	path, _ := cmd.Flags().GetString("config")
	cfg, err := runtimeconfig.LoadRelay(runtimeconfig.ClientOptions{Path: path})
	if err != nil {
		return runtimeconfig.RelayClient{}, err
	}
	if cmd.Flags().Changed("listen") {
		cfg.Relay.ListenAddress, _ = cmd.Flags().GetString("listen")
	}
	if cmd.Flags().Changed("remote") {
		cfg.Relay.RemoteAddress, _ = cmd.Flags().GetString("remote")
	}
	if cmd.Flags().Changed("listener-mode") {
		cfg.Relay.ListenerMode, _ = cmd.Flags().GetString("listener-mode")
	}
	if err := runtimeconfig.ValidateRelay(cfg.Relay); err != nil {
		return runtimeconfig.RelayClient{}, err
	}
	return cfg, nil
}

func relayTrustDomains(rawDomains []string) ([]spiffeid.TrustDomain, error) {
	domains := make([]spiffeid.TrustDomain, 0, len(rawDomains))
	for _, raw := range rawDomains {
		domain, err := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
		if err != nil {
			return nil, fmt.Errorf("invalid relay SPIFFE trust domain %q: %w", raw, err)
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

func init() {
	relayCmd.Flags().String("config", "", "path to versioned TOML configuration")
	relayCmd.Flags().String("listen", "", "override relay listen address")
	relayCmd.Flags().String("remote", "", "override central proxy host:port")
	relayCmd.Flags().String("listener-mode", "", "override relay listener mode (loopback or network)")
	rootCmd.AddCommand(relayCmd)
}
