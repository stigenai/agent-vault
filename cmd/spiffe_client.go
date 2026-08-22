package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var cliWorkloadIdentity struct {
	sync.Mutex
	key    string
	source *workloadidentity.Source
}

var loadWorkloadIdentitySession = ensureWorkloadIdentitySession

func ensureWorkloadIdentitySession() (*session.ClientSession, error) {
	client, err := runtimeconfig.LoadClient(runtimeconfig.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("load CLI workload identity configuration: %w", err)
	}
	if client.WorkloadAPI == "" {
		return nil, nil
	}
	key := client.Address + "\x00" + client.WorkloadAPI + "\x00" + strings.Join(client.TrustDomains, "\x00")

	cliWorkloadIdentity.Lock()
	defer cliWorkloadIdentity.Unlock()
	if cliWorkloadIdentity.source == nil || cliWorkloadIdentity.key != key {
		if cliWorkloadIdentity.source != nil {
			_ = cliWorkloadIdentity.source.Close()
			cliWorkloadIdentity.source = nil
		}
		domains := make([]spiffeid.TrustDomain, 0, len(client.TrustDomains))
		for _, raw := range client.TrustDomains {
			domain, err := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
			if err != nil {
				return nil, fmt.Errorf("invalid CLI SPIFFE trust domain %q: %w", raw, err)
			}
			domains = append(domains, domain)
		}
		source, err := workloadidentity.New(context.Background(), workloadidentity.Options{Address: client.WorkloadAPI})
		if err != nil {
			return nil, fmt.Errorf("connect to SPIRE Workload API socket %q: %w; ensure the socket is mounted and this workload has a SPIRE registration entry", client.WorkloadAPI, err)
		}
		tlsConfig, err := source.ClientTLSConfig(workloadidentity.AuthorizeTrustDomains(domains...))
		if err != nil {
			_ = source.Close()
			return nil, fmt.Errorf("configure CLI SPIFFE mTLS: %w", err)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		// Control-plane mTLS must connect directly. In particular, ignore
		// HTTP_PROXY inherited from an Agent Vault relay/proxy environment.
		transport.Proxy = nil
		httpClient.Transport = &clientHeaderTransport{base: &spiffeRoundTripper{base: transport}}
		cliWorkloadIdentity.key = key
		cliWorkloadIdentity.source = source
	}

	return &session.ClientSession{
		Address:          strings.TrimRight(client.Address, "/"),
		WorkloadIdentity: true,
	}, nil
}

type spiffeRoundTripper struct {
	base http.RoundTripper
}

func (t *spiffeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("SPIFFE mTLS request failed: %w; verify the server trust domain and SPIRE bundle", err)
	}
	return resp, nil
}

func closeWorkloadIdentityClient() {
	cliWorkloadIdentity.Lock()
	defer cliWorkloadIdentity.Unlock()
	if cliWorkloadIdentity.source != nil {
		_ = cliWorkloadIdentity.source.Close()
		cliWorkloadIdentity.source = nil
		cliWorkloadIdentity.key = ""
	}
}

func activeWorkloadIdentitySource() (*workloadidentity.Source, error) {
	if _, err := ensureWorkloadIdentitySession(); err != nil {
		return nil, err
	}
	cliWorkloadIdentity.Lock()
	defer cliWorkloadIdentity.Unlock()
	if cliWorkloadIdentity.source == nil {
		return nil, fmt.Errorf("CLI workload identity source is unavailable")
	}
	return cliWorkloadIdentity.source, nil
}

func workloadIdentityAddress() (string, bool, error) {
	sess, err := loadWorkloadIdentitySession()
	if err != nil {
		return "", false, err
	}
	if sess == nil {
		return "", false, nil
	}
	return sess.Address, true, nil
}
