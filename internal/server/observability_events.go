package server

import (
	"context"
	"log/slog"
	"time"
)

// runIdentityObservability emits only state transitions and remaining
// lifetime. It deliberately omits the SPIFFE ID and certificate details.
func (s *Server) runIdentityObservability(ctx context.Context) {
	if s.metricsIdentity == nil {
		return
	}
	s.logIdentityStatus()
	updates := s.metricsIdentity.Updated()
	if updates == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-updates:
			if !ok {
				return
			}
			s.logIdentityStatus()
		}
	}
}

func (s *Server) logIdentityStatus() {
	expiresAt, err := s.metricsIdentity.ExpiresAt()
	if err != nil {
		s.logger.Warn("SPIFFE workload identity unavailable",
			slog.String("event", "spiffe_identity"),
			slog.String("outcome", "unavailable"))
		return
	}
	s.logger.Info("SPIFFE workload identity ready",
		slog.String("event", "spiffe_identity"),
		slog.String("outcome", "ready"),
		slog.Int64("seconds_until_expiry", maxInt64(0, int64(time.Until(expiresAt).Seconds()))))
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
