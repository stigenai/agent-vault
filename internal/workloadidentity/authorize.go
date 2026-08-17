package workloadidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const agentLookupTimeout = 2 * time.Second

// AgentLookup is the narrow persistence surface needed to bind a validated
// SPIFFE identity to an Agent Vault actor.
type AgentLookup interface {
	GetAgentBySPIFFEID(ctx context.Context, spiffeID string) (*store.Agent, error)
}

// AuthorizeAgents returns a handshake authorizer that permits only exact,
// active agent identities in one of the configured trust domains. Certificate
// chain validation is performed by go-spiffe before this callback is invoked.
func AuthorizeAgents(lookup AgentLookup, trustDomains ...spiffeid.TrustDomain) tlsconfig.Authorizer {
	allowed := make(map[spiffeid.TrustDomain]struct{}, len(trustDomains))
	for _, trustDomain := range trustDomains {
		allowed[trustDomain] = struct{}{}
	}

	return func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		if lookup == nil || len(allowed) == 0 || len(verifiedChains) == 0 {
			return fmt.Errorf("SPIFFE peer is not authorized")
		}
		if _, ok := allowed[id.TrustDomain()]; !ok {
			return fmt.Errorf("SPIFFE trust domain is not authorized")
		}

		ctx, cancel := context.WithTimeout(context.Background(), agentLookupTimeout)
		defer cancel()
		agent, err := lookup.GetAgentBySPIFFEID(ctx, id.String())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("SPIFFE peer is not registered")
			}
			return fmt.Errorf("resolve SPIFFE peer: %w", err)
		}
		if !activeExactAgent(agent, id.String()) {
			return fmt.Errorf("SPIFFE peer is not active")
		}
		return nil
	}
}

// AgentFromTLS maps an already verified TLS peer to its current agent record.
// The lookup is repeated per request so revocation also takes effect on reused
// HTTP connections, not only at the next TLS handshake.
func AgentFromTLS(ctx context.Context, state *tls.ConnectionState, lookup AgentLookup) (*store.Agent, error) {
	if lookup == nil || state == nil || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("verified SPIFFE client certificate required")
	}
	id, err := x509svid.IDFromCert(state.PeerCertificates[0])
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE client certificate: %w", err)
	}
	agent, err := lookup.GetAgentBySPIFFEID(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("resolve SPIFFE peer: %w", err)
	}
	if !activeExactAgent(agent, id.String()) {
		return nil, fmt.Errorf("SPIFFE peer is not active")
	}
	return agent, nil
}

func activeExactAgent(agent *store.Agent, id string) bool {
	return agent != nil && agent.Status == "active" && agent.SPIFFEID == id && agent.RevokedAt == nil
}
