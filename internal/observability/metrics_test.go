package observability

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMetricsUseOnlyBoundedLabelsAndOperationalValues(t *testing.T) {
	registry := New()
	registry.RecordFleetApply("conflict")
	registry.RecordRefreshCycle(2, nil)
	registry.RecordRelayDial(false)
	registry.AddRelayConnection(1)
	now := time.Unix(1_700_000_000, 0).UTC()
	var server bytes.Buffer
	err := registry.WriteServer(&server, ServerSnapshot{
		DatabaseBackend:  "postgres",
		DatabaseUp:       true,
		SPIFFEConfigured: true,
		SPIFFEUp:         true,
		SVIDExpiresAt:    now.Add(time.Hour),
		DEKUnwrapUp:      true,
		CredentialSourceHealth: map[string]int{
			"ok": 3, "stale": 1,
		},
		RefreshFailures:      2,
		OldestSuccessAge:     4 * time.Minute,
		SecondsUntilStale:    30 * time.Second,
		HasStalenessDeadline: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	text := server.String()
	for _, want := range []string{
		`agent_vault_database_up{backend="postgres"} 1`,
		`agent_vault_secret_sources{health="stale"} 1`,
		"agent_vault_spiffe_svid_seconds_until_expiry 3600",
		"agent_vault_fleet_reconcile_conflicts_total 1",
		"agent_vault_secret_refresh_source_failures_total 2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"spiffe://", "vault_id", "agent_id", "provider_name", "reference", "dsn", "token"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("metrics contain forbidden field %q:\n%s", forbidden, text)
		}
	}

	var relay bytes.Buffer
	if err := registry.WriteRelay(&relay, RelaySnapshot{SPIFFEUp: true, SVIDExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	if got := relay.String(); !strings.Contains(got, "agent_vault_relay_dial_failures_total 1") || !strings.Contains(got, "agent_vault_relay_active_connections 1") {
		t.Fatalf("relay metrics missing connectivity state:\n%s", got)
	}
}
