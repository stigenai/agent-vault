// Package workloadidentity provides rotating SPIFFE X.509 identity material
// sourced from the SPIRE Workload API without exposing private keys to callers.
package workloadidentity

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type materialSource interface {
	x509svid.Source
	x509bundle.Source
}

type updateSource interface {
	Updated() <-chan struct{}
}

type Options struct {
	Address string
}

// Source owns a live Workload API subscription. X509-SVID and bundle updates
// are consumed by TLS callbacks without restarting listeners or clients.
type Source struct {
	material materialSource
	close    func() error
	now      func() time.Time
	once     sync.Once
	closeErr error
}

// New connects to a Unix Workload API socket and blocks until the first valid
// X.509-SVID update arrives or ctx is cancelled.
func New(ctx context.Context, opts Options) (*Source, error) {
	if err := validateAddress(opts.Address); err != nil {
		return nil, err
	}
	workloadSource, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(opts.Address)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect SPIRE Workload API: %w", err)
	}
	source := newSource(workloadSource, workloadSource.Close)
	if err := source.Ready(); err != nil {
		_ = workloadSource.Close()
		return nil, fmt.Errorf("initial SPIFFE identity: %w", err)
	}
	return source, nil
}

func newSource(material materialSource, closeFn func() error) *Source {
	if closeFn == nil {
		closeFn = func() error { return nil }
	}
	return &Source{material: material, close: closeFn, now: time.Now}
}

func validateAddress(address string) error {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "unix" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(parsed.Path) {
		return fmt.Errorf("workload API address must be an absolute unix:// socket")
	}
	for _, element := range strings.Split(filepath.ToSlash(parsed.Path), "/") {
		if element == ".." {
			return fmt.Errorf("workload API address must not contain traversal")
		}
	}
	return nil
}

// Ready reports whether the current SVID has a signer and an unexpired leaf
// certificate matching its exact SPIFFE ID.
func (s *Source) Ready() error {
	_, err := s.current()
	return err
}

func (s *Source) current() (*x509svid.SVID, error) {
	if s == nil || s.material == nil {
		return nil, fmt.Errorf("SPIFFE identity source is unavailable")
	}
	svid, err := s.material.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("get X.509-SVID: %w", err)
	}
	if svid == nil || svid.PrivateKey == nil || len(svid.Certificates) == 0 {
		return nil, fmt.Errorf("X.509-SVID has incomplete key material")
	}
	leaf := svid.Certificates[0]
	now := s.now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("X.509-SVID is not valid yet")
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("X.509-SVID is expired")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != svid.ID.String() {
		return nil, fmt.Errorf("X.509-SVID certificate identity mismatch")
	}
	return svid, nil
}

// ID returns only public identity metadata after readiness validation.
func (s *Source) ID() (spiffeid.ID, error) {
	svid, err := s.current()
	if err != nil {
		return spiffeid.ID{}, err
	}
	return svid.ID, nil
}

func (s *Source) ExpiresAt() (time.Time, error) {
	svid, err := s.current()
	if err != nil {
		return time.Time{}, err
	}
	return svid.Certificates[0].NotAfter, nil
}

// ClientTLSConfig returns an mTLS client config whose certificate callbacks
// consult the live source on every handshake.
func (s *Source) ClientTLSConfig(authorizer tlsconfig.Authorizer) (*tls.Config, error) {
	if authorizer == nil {
		return nil, fmt.Errorf("SPIFFE peer authorizer is required")
	}
	if err := s.Ready(); err != nil {
		return nil, err
	}
	return tlsconfig.MTLSClientConfig(s.material, s.material, authorizer), nil
}

// ServerTLSConfig returns an mTLS server config whose certificate callbacks
// consult the live source on every handshake.
func (s *Source) ServerTLSConfig(authorizer tlsconfig.Authorizer) (*tls.Config, error) {
	if authorizer == nil {
		return nil, fmt.Errorf("SPIFFE peer authorizer is required")
	}
	if err := s.Ready(); err != nil {
		return nil, err
	}
	return tlsconfig.MTLSServerConfig(s.material, s.material, authorizer), nil
}

// HybridServerTLSConfig presents the rotating server SVID and validates a
// client SVID when one is presented, while still allowing legacy clients to
// authenticate at the HTTP layer. A presented invalid SVID fails the TLS
// handshake and therefore cannot downgrade to a bearer token.
func (s *Source) HybridServerTLSConfig(authorizer tlsconfig.Authorizer) (*tls.Config, error) {
	if authorizer == nil {
		return nil, fmt.Errorf("SPIFFE peer authorizer is required")
	}
	if err := s.Ready(); err != nil {
		return nil, err
	}
	config := tlsconfig.TLSServerConfig(s.material)
	config.ClientAuth = tls.RequestClientCert
	verify := tlsconfig.VerifyPeerCertificate(s.material, authorizer)
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return nil
		}
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, peer := range state.PeerCertificates {
			rawCerts[i] = peer.Raw
		}
		return verify(rawCerts, state.VerifiedChains)
	}
	return config, nil
}

// Updated signals whenever the Workload API publishes new SVID or bundle
// material. A nil channel means the injected source does not support signals.
func (s *Source) Updated() <-chan struct{} {
	if updates, ok := s.material.(updateSource); ok {
		return updates.Updated()
	}
	return nil
}

func (s *Source) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() { s.closeErr = s.close() })
	return s.closeErr
}
