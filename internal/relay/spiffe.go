package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type SPIFFEDialOptions struct {
	Source       *workloadidentity.Source
	TrustDomains []spiffeid.TrustDomain
	DialContext  DialContextFunc
}

// NewSPIFFEDialContext creates the relay-to-broker transport. The returned
// dialer authenticates every new central connection with the source's current
// X.509-SVID and verifies the broker against an exact configured trust-domain
// allowlist. No bearer token or exportable key material is produced.
func NewSPIFFEDialContext(opts SPIFFEDialOptions) (DialContextFunc, error) {
	if opts.Source == nil {
		return nil, errors.New("relay SPIFFE identity source is required")
	}
	if len(opts.TrustDomains) == 0 {
		return nil, errors.New("at least one relay broker trust domain is required")
	}
	tlsConfig, err := opts.Source.ClientTLSConfig(workloadidentity.AuthorizeTrustDomains(opts.TrustDomains...))
	if err != nil {
		return nil, fmt.Errorf("prepare relay SPIFFE mTLS: %w", err)
	}
	return newMTLSDialContext(tlsConfig, opts.DialContext)
}

func newMTLSDialContext(tlsConfig *tls.Config, base DialContextFunc) (DialContextFunc, error) {
	if tlsConfig == nil {
		return nil, errors.New("relay TLS configuration is required")
	}
	if base == nil {
		dialer := &net.Dialer{}
		base = dialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := base(ctx, network, address)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, tlsConfig.Clone())
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("authenticate central proxy with SPIFFE mTLS: %w", err)
		}
		return conn, nil
	}, nil
}
