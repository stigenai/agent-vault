package workloadidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type fakeAgentLookup map[string]*store.Agent

func (f fakeAgentLookup) GetAgentBySPIFFEID(_ context.Context, id string) (*store.Agent, error) {
	agent, ok := f[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return agent, nil
}

func TestAuthorizeAgentsRequiresPermittedExactActiveAgent(t *testing.T) {
	now := time.Now().UTC()
	svid := testSVID(t, "spiffe://cluster.example/ns/agents/sa/worker", now.Add(-time.Minute), now.Add(time.Hour))
	other := testSVID(t, "spiffe://other.example/ns/agents/sa/worker", now.Add(-time.Minute), now.Add(time.Hour))
	domain := spiffeid.RequireTrustDomainFromString("cluster.example")
	chains := [][]*x509.Certificate{{svid.Certificates[0]}}

	lookup := fakeAgentLookup{svid.ID.String(): {
		ID: "agent-1", SPIFFEID: svid.ID.String(), Status: "active",
	}}
	authorize := AuthorizeAgents(lookup, domain)
	if err := authorize(svid.ID, chains); err != nil {
		t.Fatalf("known active identity rejected: %v", err)
	}
	if err := authorize(other.ID, [][]*x509.Certificate{{other.Certificates[0]}}); err == nil {
		t.Fatal("wrong trust domain was authorized")
	}
	if err := authorize(spiffeid.RequireFromString("spiffe://cluster.example/unknown"), chains); err == nil {
		t.Fatal("unknown exact identity was authorized")
	}

	lookup[svid.ID.String()].Status = "revoked"
	when := now
	lookup[svid.ID.String()].RevokedAt = &when
	if err := authorize(svid.ID, chains); err == nil {
		t.Fatal("revoked identity was authorized")
	}
	if err := AuthorizeAgents(lookup)(svid.ID, chains); err == nil {
		t.Fatal("empty trust-domain policy was authorized")
	}
}

func TestAgentFromTLSRequiresVerifiedPeerAndRechecksRevocation(t *testing.T) {
	now := time.Now().UTC()
	svid := testSVID(t, "spiffe://cluster.example/workload", now.Add(-time.Minute), now.Add(time.Hour))
	agent := &store.Agent{ID: "agent-1", SPIFFEID: svid.ID.String(), Status: "active"}
	lookup := fakeAgentLookup{svid.ID.String(): agent}
	state := &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  svid.Certificates,
	}

	got, err := AgentFromTLS(context.Background(), state, lookup)
	if err != nil || got.ID != agent.ID {
		t.Fatalf("AgentFromTLS() = (%v, %v)", got, err)
	}
	if _, err := AgentFromTLS(context.Background(), &tls.ConnectionState{HandshakeComplete: true}, lookup); err == nil {
		t.Fatal("missing client certificate was accepted")
	}

	agent.Status = "revoked"
	when := now
	agent.RevokedAt = &when
	if _, err := AgentFromTLS(context.Background(), state, lookup); err == nil {
		t.Fatal("revoked identity remained authorized on reused connection")
	}
}
