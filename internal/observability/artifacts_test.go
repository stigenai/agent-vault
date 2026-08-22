package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFleetDashboardAndAlertsAreValidAndSecretSafe(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "kubernetes", "fleet", "observability")
	rules, err := os.ReadFile(filepath.Join(root, "prometheus-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ruleDocument map[string]any
	if err := yaml.Unmarshal(rules, &ruleDocument); err != nil {
		t.Fatalf("parse Prometheus rules: %v", err)
	}
	dashboardYAML, err := os.ReadFile(filepath.Join(root, "grafana-dashboard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var dashboardConfig struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(dashboardYAML, &dashboardConfig); err != nil {
		t.Fatalf("parse dashboard ConfigMap: %v", err)
	}
	dashboard := dashboardConfig.Data["agent-vault-fleet.json"]
	if !json.Valid([]byte(dashboard)) {
		t.Fatal("embedded Grafana dashboard is not valid JSON")
	}

	combined := strings.ToLower(string(rules) + "\n" + dashboard)
	for _, forbidden := range []string{
		"spiffe_id", "credential_key", "provider_name", "provider_reference",
		"database_url", "dsn", "bearer", "token", "secret_value", "$labels",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("observability artifact contains forbidden dynamic or secret-bearing field %q", forbidden)
		}
	}
	for _, required := range []string{
		"agent_vault_spiffe_svid_seconds_until_expiry",
		"agent_vault_secret_source_seconds_until_stale",
		"agent_vault_fleet_reconcile_conflicts_total",
		"agent_vault_relay_dial_failures_total",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("observability artifacts omit %q", required)
		}
	}
}
