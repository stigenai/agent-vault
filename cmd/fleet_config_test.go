package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
)

func TestFleetConfigPlanAndGuardedApplyUseWorkloadIdentity(t *testing.T) {
	var applyCalls int
	var applied struct {
		Manifest           *fleetconfig.Manifest        `json:"manifest"`
		Options            fleetplan.Options            `json:"options"`
		ExpectedPlanSHA256 string                       `json:"expected_plan_sha256"`
		Imports            []fleetResolvedImportPayload `json:"imports"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("workload request sent bearer authorization: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/fleet/provider-reference/validate":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"kind": secretprovider.KindAWSSecretsManager, "canonical": "canonical/" + request["ref"],
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/fleet/state":
			_ = json.NewEncoder(w).Encode(fleetstate.State{SchemaVersion: fleetstate.SchemaVersion})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/fleet/apply":
			applyCalls++
			if err := json.NewDecoder(r.Body).Decode(&applied); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"plan_sha256": applied.ExpectedPlanSHA256, "applied": []any{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalIdentity := loadWorkloadIdentitySession
	originalHTTPClient := httpClient
	loadWorkloadIdentitySession = func() (*session.ClientSession, error) {
		return &session.ClientSession{Address: server.URL, WorkloadIdentity: true}, nil
	}
	httpClient = server.Client()
	t.Cleanup(func() {
		loadWorkloadIdentitySession = originalIdentity
		httpClient = originalHTTPClient
	})

	path := filepath.Join(t.TempDir(), "fleet.toml")
	t.Setenv("FLEET_IMPORTED_TOKEN", "restore-after-test")
	if err := os.Unsetenv("FLEET_IMPORTED_TOKEN"); err != nil {
		t.Fatal(err)
	}
	manifest := `schema_version = 1
manager = "platform-fleet"

[[agents]]
name = "worker"
spiffe_id = "spiffe://cluster.example/ns/agents/sa/worker"
role = "no-access"

[[vaults]]
name = "automation"

[[vaults.grants]]
agent = "worker"
role = "proxy"

[[vaults.credentials]]
name = "TOKEN"
mode = "reference"
source = "aws-production"
ref = "application/token"
refresh_interval = "1m"
max_staleness = "5m"

[[vaults.imports]]
name = "IMPORTED_TOKEN"
from = "env://FLEET_IMPORTED_TOKEN"
`
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	planCmd := newFleetTestCommand()
	if err := planCmd.Flags().Set("file", path); err != nil {
		t.Fatal(err)
	}
	input, err := buildFleetCommandInput(planCmd)
	if err != nil {
		t.Fatal(err)
	}
	if input.Plan.Blocked || input.Plan.Summary.Create != 5 || input.Digest == "" {
		t.Fatalf("plan = %#v digest=%q", input.Plan, input.Digest)
	}
	var planOutput bytes.Buffer
	if err := writeFleetPlan(&planOutput, input.Plan, input.Digest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planOutput.String(), "env://") || strings.Contains(planOutput.String(), "cli-import-secret-value") || !strings.Contains(planOutput.String(), input.Digest) {
		t.Fatalf("unexpected plan output: %s", planOutput.String())
	}

	applyCmd := newFleetTestCommand()
	applyCmd.RunE = fleetConfigApplyCmd.RunE
	applyCmd.Flags().String("plan-sha256", "", "")
	applyCmd.Flags().BoolP("yes", "y", false, "")
	if err := applyCmd.Flags().Set("file", path); err != nil {
		t.Fatal(err)
	}
	if err := applyCmd.RunE(applyCmd, nil); err == nil || !strings.Contains(err.Error(), "--plan-sha256") {
		t.Fatalf("apply without approval error = %v", err)
	}
	if applyCalls != 0 {
		t.Fatal("apply request was sent without approval")
	}
	if err := os.Setenv("FLEET_IMPORTED_TOKEN", "cli-import-secret-value"); err != nil {
		t.Fatal(err)
	}
	if err := applyCmd.Flags().Set("plan-sha256", input.Digest); err != nil {
		t.Fatal(err)
	}
	var applyOutput bytes.Buffer
	applyCmd.SetOut(&applyOutput)
	if err := applyCmd.RunE(applyCmd, nil); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 || applied.ExpectedPlanSHA256 != input.Digest {
		t.Fatalf("apply calls=%d request=%#v", applyCalls, applied)
	}
	if len(applied.Imports) != 1 || string(applied.Imports[0].Value) != "cli-import-secret-value" {
		t.Fatalf("resolved imports = %#v", applied.Imports)
	}
	if strings.Contains(applyOutput.String(), "cli-import-secret-value") {
		t.Fatalf("apply output leaked imported value: %s", applyOutput.String())
	}
	credential := applied.Manifest.Vaults[0].Credentials[0]
	if credential.Reference != "canonical/application/token" || credential.ProviderKind != secretprovider.KindAWSSecretsManager {
		t.Fatalf("apply did not send canonical manifest: %#v", credential)
	}
}

func newFleetTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	addFleetConfigFlags(cmd)
	return cmd
}
