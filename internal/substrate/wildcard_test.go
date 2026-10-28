package substrate

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/substrate/credproviderpb"
)

func TestFetchSecretAtespaceWildcard(t *testing.T) {
	const (
		wildcard = "spiffe://substrate-actor.local/actor/factory/*"
		other    = "spiffe://substrate-actor.local/actor/other/*"
		task     = "spiffe://substrate-actor.local/actor/factory/f-run-1"
		uri      = "ate-secret://agent-vault/team-a/GITHUB_TOKEN"
	)
	revokedAt := time.Now()
	active := func(id string) map[string]*store.Agent {
		return map[string]*store.Agent{id: {ID: "w", SPIFFEID: id, Status: "active"}}
	}
	granted := map[[2]string]string{{"w", "v1"}: "proxy"}
	cases := []struct {
		name   string
		actor  string
		agents map[string]*store.Agent
		grants map[[2]string]string
		code   codes.Code
		looked []string // nil: not checked
	}{
		{"exact granted", task,
			map[string]*store.Agent{task: {ID: "e", SPIFFEID: task, Status: "active"}},
			map[[2]string]string{{"e", "v1"}: "proxy"}, codes.OK, []string{task}},
		{"no exact, wildcard granted", task, active(wildcard), granted, codes.OK, []string{task, wildcard}},
		{"wildcard for a different atespace", task, active(other), granted, codes.PermissionDenied, nil},
		{"wildcard without grant", task, active(wildcard), nil, codes.PermissionDenied, nil},
		{"wildcard revoked", task,
			map[string]*store.Agent{wildcard: {ID: "w", SPIFFEID: wildcard, Status: "revoked", RevokedAt: &revokedAt}},
			granted, codes.PermissionDenied, nil},
		{"wildcard inactive", task,
			map[string]*store.Agent{wildcard: {ID: "w", SPIFFEID: wildcard, Status: "pending"}},
			granted, codes.PermissionDenied, nil},
		{"exact without grant does not fall through to granted wildcard", task,
			map[string]*store.Agent{
				task:     {ID: "e", SPIFFEID: task, Status: "active"},
				wildcard: {ID: "w", SPIFFEID: wildcard, Status: "active"},
			},
			granted, codes.PermissionDenied, []string{task}},
		{"wildcard record stored under a different SPIFFE ID", task,
			map[string]*store.Agent{wildcard: {ID: "w", SPIFFEID: task + "x", Status: "active"}},
			granted, codes.PermissionDenied, nil},
		{"malformed: too few segments", "spiffe://substrate-actor.local/actor/factory",
			active(wildcard), granted, codes.PermissionDenied, []string{"spiffe://substrate-actor.local/actor/factory"}},
		{"malformed: too many segments", "spiffe://substrate-actor.local/actor/factory/a/b",
			active(wildcard), granted, codes.PermissionDenied, []string{"spiffe://substrate-actor.local/actor/factory/a/b"}},
		{"malformed: not an actor path", "spiffe://substrate-actor.local/ns/factory/f-run-1",
			active(wildcard), granted, codes.PermissionDenied, []string{"spiffe://substrate-actor.local/ns/factory/f-run-1"}},
		{"wrong trust domain", "spiffe://other.local/actor/factory/f-run-1",
			active("spiffe://other.local/actor/factory/*"), granted, codes.PermissionDenied, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, fs := newFixture(t)
			fs.agents, fs.grants = tc.agents, tc.grants
			_, err := p.FetchSecret(context.Background(), &credproviderpb.FetchSecretRequest{Uri: uri, ActorSpiffeId: tc.actor})
			if got := status.Code(err); got != tc.code {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.code)
			}
			if tc.looked != nil && !slices.Equal(fs.looked, tc.looked) {
				t.Fatalf("lookups = %v, want %v", fs.looked, tc.looked)
			}
		})
	}
}
