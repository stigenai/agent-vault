// Package observability exposes bounded-cardinality operational metrics.
// Metric labels are deliberately fixed enumerations; caller-controlled names,
// identities, references, addresses, and error strings have no representation.
package observability

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

type Registry struct {
	fleetApplySuccess      atomic.Uint64
	fleetApplyConflicts    atomic.Uint64
	fleetApplyFailures     atomic.Uint64
	refreshCycles          atomic.Uint64
	refreshCycleErrors     atomic.Uint64
	refreshSourceFailures  atomic.Uint64
	relayDialSuccess       atomic.Uint64
	relayDialFailures      atomic.Uint64
	relayActiveConnections atomic.Int64
	relayLastSuccessUnix   atomic.Int64
}

type ServerSnapshot struct {
	DatabaseBackend        string
	DatabaseUp             bool
	SPIFFEConfigured       bool
	SPIFFEUp               bool
	SVIDExpiresAt          time.Time
	DEKUnwrapUp            bool
	CredentialSourceHealth map[string]int
	RefreshFailures        int
	OldestSuccessAge       time.Duration
	SecondsUntilStale      time.Duration
	HasStalenessDeadline   bool
}

type RelaySnapshot struct {
	SPIFFEUp      bool
	SVIDExpiresAt time.Time
}

func New() *Registry { return &Registry{} }

func (r *Registry) RecordFleetApply(outcome string) {
	if r == nil {
		return
	}
	switch outcome {
	case "success":
		r.fleetApplySuccess.Add(1)
	case "conflict":
		r.fleetApplyConflicts.Add(1)
	default:
		r.fleetApplyFailures.Add(1)
	}
}

func (r *Registry) RecordRefreshCycle(failedSources int, err error) {
	if r == nil {
		return
	}
	r.refreshCycles.Add(1)
	if err != nil {
		r.refreshCycleErrors.Add(1)
	}
	if failedSources > 0 {
		r.refreshSourceFailures.Add(uint64(failedSources))
	}
}

func (r *Registry) RecordRelayDial(success bool) {
	if r == nil {
		return
	}
	if success {
		r.relayDialSuccess.Add(1)
		r.relayLastSuccessUnix.Store(time.Now().Unix())
		return
	}
	r.relayDialFailures.Add(1)
}

func (r *Registry) AddRelayConnection(delta int64) {
	if r != nil {
		r.relayActiveConnections.Add(delta)
	}
}

func (r *Registry) WriteServer(w io.Writer, snapshot ServerSnapshot, now time.Time) error {
	if r == nil {
		return nil
	}
	backend := snapshot.DatabaseBackend
	if backend != "postgres" && backend != "sqlite" {
		backend = "unknown"
	}
	metric := func(name, help, typ, labels string, value any) error {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s%s %v\n", name, help, name, typ, name, labels, value); err != nil {
			return err
		}
		return nil
	}
	if err := metric("agent_vault_database_up", "Whether the configured database responds to a bounded health check.", "gauge", `{backend="`+backend+`"}`, boolNumber(snapshot.DatabaseUp)); err != nil {
		return err
	}
	if err := metric("agent_vault_dek_unwrap_up", "Whether the broker completed DEK unwrap before serving.", "gauge", "", boolNumber(snapshot.DEKUnwrapUp)); err != nil {
		return err
	}
	if snapshot.SPIFFEConfigured {
		if err := metric("agent_vault_spiffe_svid_up", "Whether the current workload X.509-SVID is valid.", "gauge", "", boolNumber(snapshot.SPIFFEUp)); err != nil {
			return err
		}
		if !snapshot.SVIDExpiresAt.IsZero() {
			if err := metric("agent_vault_spiffe_svid_expiry_timestamp_seconds", "Unix expiry time of the current workload X.509-SVID.", "gauge", "", snapshot.SVIDExpiresAt.Unix()); err != nil {
				return err
			}
			if err := metric("agent_vault_spiffe_svid_seconds_until_expiry", "Seconds until the current workload X.509-SVID expires.", "gauge", "", maxFloat(0, snapshot.SVIDExpiresAt.Sub(now).Seconds())); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprint(w, "# HELP agent_vault_secret_sources Credential sources by bounded health state.\n# TYPE agent_vault_secret_sources gauge\n"); err != nil {
		return err
	}
	for _, health := range []string{"pending", "ok", "error", "stale"} {
		if _, err := fmt.Fprintf(w, "agent_vault_secret_sources{health=%q} %d\n", health, snapshot.CredentialSourceHealth[health]); err != nil {
			return err
		}
	}
	if err := metric("agent_vault_secret_source_consecutive_refresh_failures", "Sum of current consecutive refresh failures across credential sources.", "gauge", "", snapshot.RefreshFailures); err != nil {
		return err
	}
	if snapshot.OldestSuccessAge > 0 {
		if err := metric("agent_vault_secret_source_oldest_success_age_seconds", "Age of the oldest last-successful credential source refresh.", "gauge", "", snapshot.OldestSuccessAge.Seconds()); err != nil {
			return err
		}
	}
	if snapshot.HasStalenessDeadline {
		if err := metric("agent_vault_secret_source_seconds_until_stale", "Smallest non-negative time until a source exceeds its last-known-good window.", "gauge", "", maxFloat(0, snapshot.SecondsUntilStale.Seconds())); err != nil {
			return err
		}
	}
	for _, counter := range []struct {
		name, help string
		value      uint64
	}{
		{"agent_vault_fleet_reconcile_success_total", "Successful fleet apply requests.", r.fleetApplySuccess.Load()},
		{"agent_vault_fleet_reconcile_conflicts_total", "Fleet apply requests rejected due to plan or revision conflicts.", r.fleetApplyConflicts.Load()},
		{"agent_vault_fleet_reconcile_failures_total", "Fleet apply requests that failed for reasons other than conflicts.", r.fleetApplyFailures.Load()},
		{"agent_vault_secret_refresh_cycles_total", "Secret refresh scheduler cycles.", r.refreshCycles.Load()},
		{"agent_vault_secret_refresh_cycle_errors_total", "Secret refresh scheduler/store cycle errors.", r.refreshCycleErrors.Load()},
		{"agent_vault_secret_refresh_source_failures_total", "Credential source refresh attempts that failed.", r.refreshSourceFailures.Load()},
	} {
		if err := metric(counter.name, counter.help, "counter", "", counter.value); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) WriteRelay(w io.Writer, snapshot RelaySnapshot, now time.Time) error {
	metric := func(name, help, typ string, value any) error {
		_, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, typ, name, value)
		return err
	}
	if err := metric("agent_vault_relay_spiffe_svid_up", "Whether the relay workload X.509-SVID is valid.", "gauge", boolNumber(snapshot.SPIFFEUp)); err != nil {
		return err
	}
	if !snapshot.SVIDExpiresAt.IsZero() {
		if err := metric("agent_vault_relay_spiffe_svid_seconds_until_expiry", "Seconds until the relay workload X.509-SVID expires.", "gauge", maxFloat(0, snapshot.SVIDExpiresAt.Sub(now).Seconds())); err != nil {
			return err
		}
	}
	for _, counter := range []struct {
		name, help string
		value      uint64
	}{
		{"agent_vault_relay_dial_success_total", "Successful central broker mTLS dials.", r.relayDialSuccess.Load()},
		{"agent_vault_relay_dial_failures_total", "Failed central broker mTLS dials.", r.relayDialFailures.Load()},
	} {
		if err := metric(counter.name, counter.help, "counter", counter.value); err != nil {
			return err
		}
	}
	if err := metric("agent_vault_relay_active_connections", "Current client streams connected through the relay.", "gauge", r.relayActiveConnections.Load()); err != nil {
		return err
	}
	if last := r.relayLastSuccessUnix.Load(); last > 0 {
		if err := metric("agent_vault_relay_last_successful_dial_timestamp_seconds", "Unix time of the last successful central broker mTLS dial.", "gauge", last); err != nil {
			return err
		}
	}
	return nil
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}

func maxFloat(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}
