package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if failure := s.readinessFailure(r.Context()); failure != "" {
		healthUnavailable(w, failure)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// handleStartup is reachable only after startup migrations, workload-identity
// acquisition, DEK unwrap, and provider construction have succeeded because
// the HTTP listener is created after those steps.
func (s *Server) handleStartup(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, map[string]string{"status": "started"})
}

// handleLive deliberately avoids external dependencies. If this handler
// cannot answer within the kubelet timeout, the process is no longer live.
func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, map[string]string{"status": "live"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if failure := s.readinessFailure(r.Context()); failure != "" {
		healthUnavailable(w, failure)
		return
	}
	jsonOK(w, map[string]string{"status": "ready"})
}

func (s *Server) readinessFailure(parent context.Context) string {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()

	if s.store.DialectName() == "postgres" {
		if err := s.store.Ping(ctx); err != nil {
			return "database unreachable"
		}
	}
	for _, check := range s.readinessChecks {
		if err := check.check(ctx); err != nil {
			return check.failure
		}
	}

	vaults, err := s.store.ListVaults(ctx)
	if err != nil {
		return "database unreachable"
	}
	now := time.Now().UTC()
	for _, vault := range vaults {
		sources, err := s.store.ListCredentialSources(ctx, vault.ID)
		if err != nil {
			return "database unreachable"
		}
		for i := range sources {
			if !store.CredentialSourceUsable(&sources[i], now) {
				return "credential sources unavailable"
			}
		}
	}
	return ""
}

func healthUnavailable(w http.ResponseWriter, failure string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "unready", "error": failure})
}

// handleStatus returns the instance initialization status (public, no auth).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"initialized":      s.initialized,
		"needs_first_user": !s.initialized,
	}

	// Expose base_url only when the operator has explicitly set
	// AGENT_VAULT_ADDR. Auto-derived fallbacks may not be reachable from a
	// remote agent, so we suppress them and let the client show a placeholder.
	if os.Getenv("AGENT_VAULT_ADDR") != "" {
		resp["base_url"] = s.BaseURL()
	}

	// Read all settings in one query instead of two separate reads.
	if settings, err := s.store.GetAllSettings(r.Context()); err == nil {
		if raw, ok := settings[settingAllowedDomains]; ok {
			var domains []string
			if json.Unmarshal([]byte(raw), &domains) == nil && len(domains) > 0 {
				resp["allowed_email_domains"] = domains
			}
		}
		if raw, ok := settings[settingInviteOnly]; ok && raw == "true" {
			resp["invite_only"] = true
		}
	}

	jsonOK(w, resp)
}

// handleSPA serves the SPA index.html for client-side routing.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	indexHTML, err := fs.ReadFile(webDistFS, "webdist/index.html")
	if err != nil {
		http.Error(w, "Frontend not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}
