package server

import (
	"context"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/observability"
	"github.com/Infisical/agent-vault/internal/store"
)

type operationalMetricsStore interface {
	ListAllCredentialSources(context.Context) ([]store.CredentialSource, error)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	snapshot := observability.ServerSnapshot{
		DatabaseBackend:        s.store.DialectName(),
		DEKUnwrapUp:            len(s.encKey) == 32,
		CredentialSourceHealth: map[string]int{},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err == nil {
		snapshot.DatabaseUp = true
		metricsStore, ok := s.store.(operationalMetricsStore)
		if !ok {
			snapshot.DatabaseUp = false
		} else if sources, err := metricsStore.ListAllCredentialSources(ctx); err == nil {
			for i := range sources {
				addCredentialSourceMetrics(&snapshot, &sources[i], now)
			}
		} else {
			snapshot.DatabaseUp = false
		}
	}
	if s.metricsIdentity != nil {
		snapshot.SPIFFEConfigured = true
		if err := s.metricsIdentity.Ready(); err == nil {
			snapshot.SPIFFEUp = true
			snapshot.SVIDExpiresAt, _ = s.metricsIdentity.ExpiresAt()
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.metrics.WriteServer(w, snapshot, now); err != nil {
		s.logger.Debug("metrics response write failed", "code", "write_failed")
	}
}

func addCredentialSourceMetrics(snapshot *observability.ServerSnapshot, source *store.CredentialSource, now time.Time) {
	snapshot.CredentialSourceHealth[source.Health]++
	snapshot.RefreshFailures += source.RefreshFailures
	if source.LastSuccessAt == nil {
		return
	}
	age := now.Sub(source.LastSuccessAt.UTC())
	if age > snapshot.OldestSuccessAge {
		snapshot.OldestSuccessAge = age
	}
	if source.MaxStalenessSeconds > 0 {
		remaining := source.LastSuccessAt.Add(time.Duration(source.MaxStalenessSeconds) * time.Second).Sub(now)
		if !snapshot.HasStalenessDeadline || remaining < snapshot.SecondsUntilStale {
			snapshot.SecondsUntilStale = remaining
			snapshot.HasStalenessDeadline = true
		}
	}
}
