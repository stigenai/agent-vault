package cmd

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"strings"
	"syscall"
	"time"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	localrelay "github.com/Infisical/agent-vault/internal/relay"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Run the loopback SPIFFE proxy relay",
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
	r, err := localrelay.New(localrelay.Options{RemoteAddr: cfg.Relay.RemoteAddress, DialContext: dial})
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
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return r.Shutdown(shutdownCtx)
	}
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
	relayCmd.Flags().String("listen", "", "override relay loopback listen address")
	relayCmd.Flags().String("remote", "", "override central proxy host:port")
	rootCmd.AddCommand(relayCmd)
}
