package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestFleetStateNormalizesPersistedInlineServiceMatcher(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID:           "broker-id",
		VaultID:      "root-ns-id",
		ServicesJSON: `[{"name":"github-api","host":"api.github.com:8443/repos/stigenai/infra-blocks/*","enabled":true,"auth":{"type":"bearer","token":"GITHUB_INSTALLATION_TOKEN"}}]`,
	}

	srv := newTestServer(withStore(ms))
	state, err := srv.buildFleetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var service *fleetstate.Resource
	for index := range state.Resources {
		resource := &state.Resources[index]
		if resource.Kind == store.ManagedResourceService && resource.Name == "github-api" {
			service = resource
			break
		}
	}
	if service == nil {
		t.Fatal("github-api service missing from fleet state")
	}

	var spec fleetstate.ServiceSpec
	if err := json.Unmarshal(service.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Host != "api.github.com" || spec.Path != "/repos/stigenai/infra-blocks/*" {
		t.Fatalf("normalized matcher = host %q path %q", spec.Host, spec.Path)
	}
	if spec.Port == nil || *spec.Port != 8443 {
		t.Fatalf("normalized port = %v, want 8443", spec.Port)
	}
}
