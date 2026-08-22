package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/openbaoauth"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/awssecretsmanager"
	"github.com/Infisical/agent-vault/internal/secretprovider/onepasswordconnect"
	"github.com/Infisical/agent-vault/internal/secretprovider/openbaokv2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// fleetImportProviderSet initializes provider clients only when a manifest
// contains a provider-backed one-time import. Durable references continue to
// validate against the server registry.
type fleetImportProviderSet struct {
	once     sync.Once
	mu       sync.Mutex
	config   runtimeconfig.FleetClient
	registry *secretprovider.Registry
	built    map[string]struct{}
	closers  []io.Closer
	err      error
}

func (p *fleetImportProviderSet) Parse(name, raw string) (secretprovider.Reference, error) {
	if err := p.ensure(name); err != nil {
		return nil, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	return p.registry.Parse(name, raw)
}

func (p *fleetImportProviderSet) Fetch(ctx context.Context, name string, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := p.ensure(name); err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	return p.registry.FetchReference(ctx, name, reference)
}

func (p *fleetImportProviderSet) Close() error {
	p.mu.Lock()
	closers := p.closers
	p.closers = nil
	p.mu.Unlock()
	var first error
	for _, closer := range closers {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (p *fleetImportProviderSet) initialize() {
	p.once.Do(func() {
		p.config, p.err = runtimeconfig.LoadFleetClient(runtimeconfig.ClientOptions{})
		p.registry = secretprovider.NewRegistry()
		p.built = make(map[string]struct{})
	})
}

func (p *fleetImportProviderSet) ensure(name string) error {
	p.initialize()
	if p.err != nil {
		return p.err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.built[name]; ok {
		return nil
	}
	var configured *runtimeconfig.SecretProviderConfig
	for i := range p.config.SecretProviders {
		if p.config.SecretProviders[i].Name == name {
			configured = &p.config.SecretProviders[i]
			break
		}
	}
	if configured == nil {
		return secretprovider.NewError(secretprovider.CodeProviderNotFound)
	}
	provider, closers, err := buildFleetImportProvider(p.config, *configured)
	if err != nil {
		for _, closer := range closers {
			_ = closer.Close()
		}
		return err
	}
	if err := p.registry.Register(configured.Name, provider); err != nil {
		for _, closer := range closers {
			_ = closer.Close()
		}
		return err
	}
	p.closers = append(p.closers, closers...)
	p.built[name] = struct{}{}
	return nil
}

func buildFleetImportProvider(cfg runtimeconfig.FleetClient, configured runtimeconfig.SecretProviderConfig) (provider secretprovider.SecretProvider, closers []io.Closer, returnErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer func() {
		if returnErr != nil {
			for _, closer := range closers {
				_ = closer.Close()
			}
			closers = nil
		}
	}()
	var err error
	switch configured.Kind {
	case secretprovider.KindAWSSecretsManager:
		provider, err = awssecretsmanager.New(ctx, awssecretsmanager.Options{Region: configured.Region})
	case secretprovider.KindOpenBaoKV2:
		var tokens openbaoauth.TokenSource
		switch configured.Auth {
		case "spiffe-x509":
			identity, identityErr := activeWorkloadIdentitySource()
			if identityErr != nil {
				return nil, closers, identityErr
			}
			domains, domainErr := fleetImportTrustDomains(configured.TrustDomains, cfg.Client.TrustDomains)
			if domainErr != nil {
				return nil, closers, domainErr
			}
			tokens, err = openbaoauth.NewX509TokenSource(openbaoauth.X509Options{
				Address: configured.Address, AuthMount: configured.AuthMount, Role: configured.Role,
				Source: identity, TrustDomains: domains,
			})
		case "spiffe-jwt":
			jwtSource, sourceErr := workloadapi.NewJWTSource(ctx,
				workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.Client.WorkloadAPI)))
			if sourceErr != nil {
				return nil, closers, sourceErr
			}
			closers = append(closers, jwtSource)
			tokens, err = openbaoauth.NewJWTTokenSource(openbaoauth.JWTOptions{
				Address: configured.Address, AuthMount: configured.AuthMount, Role: configured.Role,
				Audience: configured.Audience, Source: jwtSource,
			})
		default:
			err = fmt.Errorf("unsupported OpenBao authentication")
		}
		if err == nil {
			provider, err = openbaokv2.New(openbaokv2.Options{Address: configured.Address, TokenSource: tokens})
		}
	case secretprovider.KindOnePassword:
		provider, err = onepasswordconnect.New(onepasswordconnect.Options{
			Address: configured.Address, TokenRef: configured.Token, Resolver: runtimeconfig.Resolver{},
		})
	default:
		err = fmt.Errorf("unsupported import provider")
	}
	if err != nil {
		return nil, closers, err
	}
	return provider, closers, nil
}

func fleetImportTrustDomains(configured, fallback []string) ([]spiffeid.TrustDomain, error) {
	rawDomains := configured
	if len(rawDomains) == 0 {
		rawDomains = fallback
	}
	domains := make([]spiffeid.TrustDomain, 0, len(rawDomains))
	for _, raw := range rawDomains {
		domain, err := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

var _ interface {
	Parse(string, string) (secretprovider.Reference, error)
} = (*fleetImportProviderSet)(nil)
