package openbaoauth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

type SPIFFETLSSource interface {
	ClientTLSConfig(tlsconfig.Authorizer) (*tls.Config, error)
}

type X509Options struct {
	Address      string
	AuthMount    string
	Role         string
	Source       SPIFFETLSSource
	TrustDomains []spiffeid.TrustDomain
}

type X509TokenSource struct {
	loginURL string
	role     string
	client   *http.Client
}

// NewX509TokenSource installs live TLS callbacks, so SPIRE certificate and
// bundle rotation take effect without restarting the process. It performs a
// fresh certificate login for every Token call.
func NewX509TokenSource(options X509Options) (*X509TokenSource, error) {
	address, err := validateAddress(options.Address)
	if err != nil {
		return nil, err
	}
	if options.Source == nil || len(options.TrustDomains) == 0 {
		return nil, errors.New("OpenBao SPIFFE source and trust domains are required")
	}
	mount, role, err := validateAuthMountRole(options.AuthMount, options.Role, "cert")
	if err != nil {
		return nil, err
	}
	tlsConfig, err := options.Source.ClientTLSConfig(workloadidentity.AuthorizeTrustDomains(options.TrustDomains...))
	if err != nil {
		return nil, errors.New("configure OpenBao SPIFFE transport failed")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	return &X509TokenSource{
		loginURL: address + "/v1/auth/" + mount + "/login",
		role:     role,
		client:   &http.Client{Transport: transport},
	}, nil
}

func (s *X509TokenSource) Token(ctx context.Context) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, ErrUnavailable
	}
	return login(ctx, s.client, s.loginURL, loginRequest{Name: s.role})
}

// CloseIdleConnections forces the next login to perform a new TLS handshake.
// It is primarily useful for readiness transitions and tests; live certificate
// callbacks already rotate material on each handshake.
func (s *X509TokenSource) CloseIdleConnections() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
