package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

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

// NewX509TokenSource uses live Source callbacks on every TLS handshake, so
// SPIRE certificate and bundle rotation require no process restart. Login is
// performed for each wrapping operation; returned OpenBao tokens are never
// persisted.
func NewX509TokenSource(opts X509Options) (*X509TokenSource, error) {
	address, err := validateAddress(opts.Address)
	if err != nil {
		return nil, err
	}
	if opts.Source == nil || len(opts.TrustDomains) == 0 {
		return nil, errors.New("OpenBao SPIFFE source and trust domains are required")
	}
	mount := strings.TrimSpace(opts.AuthMount)
	if mount == "" {
		mount = "cert"
	}
	if !pathSegment.MatchString(mount) || !pathSegment.MatchString(opts.Role) {
		return nil, errors.New("OpenBao certificate auth mount or role is invalid")
	}
	tlsConfig, err := opts.Source.ClientTLSConfig(workloadidentity.AuthorizeTrustDomains(opts.TrustDomains...))
	if err != nil {
		return nil, errors.New("configure OpenBao SPIFFE transport failed")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	return &X509TokenSource{
		loginURL: address + "/v1/auth/" + mount + "/login",
		role:     opts.Role,
		client:   &http.Client{Transport: transport},
	}, nil
}

func (s *X509TokenSource) Token(ctx context.Context) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"name": s.role})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.loginURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create OpenBao certificate login failed")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("OpenBao certificate login failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, errors.New("OpenBao certificate login denied")
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil || result.Auth.ClientToken == "" {
		return nil, errors.New("OpenBao certificate login returned malformed response")
	}
	return []byte(result.Auth.ClientToken), nil
}
