package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
)

type fleetCreateBarrierStore struct {
	*store.SQLStore
	arrivals chan struct{}
	release  chan struct{}
}

func (s *fleetCreateBarrierStore) CreateVault(ctx context.Context, name string) (*store.Vault, error) {
	if name == "fleet-vault" {
		s.arrivals <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.SQLStore.CreateVault(ctx, name)
}

func TestFleetConcurrentReviewedApplyHasOneWinnerAndConverges(t *testing.T) {
	database, token := setupFleetSQLStore(t)
	barrier := &fleetCreateBarrierStore{
		SQLStore: database, arrivals: make(chan struct{}, 2), release: make(chan struct{}),
	}
	srv := newTestServer(withStore(barrier), withEncKey([]byte("0123456789abcdef0123456789abcdef")))
	registry := secretprovider.NewRegistry()
	if err := registry.Register("aws-production", fleetTestProvider{}); err != nil {
		t.Fatal(err)
	}
	registry.Freeze()
	srv.AttachSecretProviderRegistry(registry)

	manifest := fleetApplyManifest()
	plan, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if plan.Summary.Create != 5 {
		t.Fatalf("initial plan = %#v", plan)
	}
	payload, err := json.Marshal(fleetApplyRequest{
		Manifest: manifest, Options: fleetplan.Options{}, ExpectedPlanSHA256: digest,
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/v1/fleet/apply", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)
			statuses <- rec.Code
		}()
	}
	close(start)
	for range 2 {
		select {
		case <-barrier.arrivals:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent applies did not reach create barrier")
		}
	}
	close(barrier.release)
	wait.Wait()
	close(statuses)
	var got []int
	for status := range statuses {
		got = append(got, status)
	}
	sort.Ints(got)
	if len(got) != 2 || got[0] != http.StatusOK || got[1] != http.StatusConflict {
		t.Fatalf("concurrent statuses = %v", got)
	}

	converged, _ := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if converged.Blocked || converged.Summary.Noop != 5 || converged.Summary.Create != 0 || converged.Summary.Update != 0 {
		t.Fatalf("post-race plan = %#v", converged)
	}
	state, err := srv.buildFleetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range state.Resources {
		if resource.Name == "fleet-vault" || resource.Name == "fleet-agent" || resource.Vault == "fleet-vault" {
			if resource.Manager != manifest.Manager || resource.Revision != 1 {
				t.Fatalf("resource ownership after race = %#v", resource)
			}
		}
	}
}

func TestFleetRealStoreStaleManagerImportAndPruneRecovery(t *testing.T) {
	database, token := setupFleetSQLStore(t)
	srv := newTestServer(withStore(database), withEncKey([]byte("0123456789abcdef0123456789abcdef")))
	manifest := fleetApplyManifest()
	manifest.Vaults[0].Credentials = nil
	manifest.Vaults[0].Imports = []fleetconfig.Import{{Name: "GITHUB_TOKEN", From: "env://GITHUB_TOKEN"}}
	_, digest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	secretValue := []byte("real-store-import-secret")
	applyTestFleetPlanWithImports(t, srv, token, manifest, digest, []fleetResolvedImport{{
		Vault: "fleet-vault", Name: "GITHUB_TOKEN", Value: secretValue,
	}}, http.StatusOK)

	vault, err := database.GetVault(context.Background(), "fleet-vault")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetCredentialSource(context.Background(), vault.ID, "GITHUB_TOKEN"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("import retained source: %v", err)
	}
	state, err := srv.buildFleetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	encodedState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedState, secretValue) || bytes.Contains(encodedState, []byte("env://GITHUB_TOKEN")) {
		t.Fatalf("fleet state leaked import material: %s", encodedState)
	}

	converged, convergedDigest := buildTestFleetPlan(t, srv, manifest, fleetplan.Options{})
	if converged.Summary.Noop != 5 {
		t.Fatalf("converged plan = %#v", converged)
	}
	repeated := applyTestFleetPlanWithImports(t, srv, token, manifest, convergedDigest, nil, http.StatusOK)
	if len(repeated.Applied) != 0 {
		t.Fatalf("repeated apply mutated state: %#v", repeated)
	}

	competitor := cloneFleetManifest(t, manifest)
	competitor.Manager = "other-manager"
	competingPlan, competingDigest := buildTestFleetPlan(t, srv, competitor, fleetplan.Options{})
	if !competingPlan.Blocked || competingPlan.Summary.Conflict != 5 {
		t.Fatalf("competing manager plan = %#v", competingPlan)
	}
	applyTestFleetPlan(t, srv, token, competitor, fleetplan.Options{}, competingDigest, http.StatusConflict)

	stale := cloneFleetManifest(t, manifest)
	stale.Vaults[0].Services[0].Host = "uploads.github.com"
	_, staleDigest := buildTestFleetPlan(t, srv, stale, fleetplan.Options{})
	intervening := cloneFleetManifest(t, manifest)
	intervening.Agents[0].Role = "member"
	_, interveningDigest := buildTestFleetPlan(t, srv, intervening, fleetplan.Options{})
	applyTestFleetPlan(t, srv, token, intervening, fleetplan.Options{}, interveningDigest, http.StatusOK)
	beforeStale, err := srv.buildFleetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	applyTestFleetPlan(t, srv, token, stale, fleetplan.Options{}, staleDigest, http.StatusConflict)
	afterStale, err := srv.buildFleetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(beforeStale)
	afterJSON, _ := json.Marshal(afterStale)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("stale apply mutated state:\n%s\n%s", beforeJSON, afterJSON)
	}
	_, recoveredDigest := buildTestFleetPlan(t, srv, stale, fleetplan.Options{})
	applyTestFleetPlan(t, srv, token, stale, fleetplan.Options{}, recoveredDigest, http.StatusOK)

	empty := &fleetconfig.Manifest{SchemaVersion: fleetconfig.SchemaVersion, Manager: manifest.Manager}
	guarded, guardedDigest := buildTestFleetPlan(t, srv, empty, fleetplan.Options{Prune: true})
	if !guarded.Blocked {
		t.Fatal("real-store credential prune was not guarded")
	}
	applyTestFleetPlan(t, srv, token, empty, fleetplan.Options{Prune: true}, guardedDigest, http.StatusConflict)
	pruneOptions := fleetplan.Options{Prune: true, PruneCredentials: true}
	prune, pruneDigest := buildTestFleetPlan(t, srv, empty, pruneOptions)
	if prune.Blocked || prune.Summary.Delete != 5 {
		t.Fatalf("real-store prune plan = %#v", prune)
	}
	applyTestFleetPlan(t, srv, token, empty, pruneOptions, pruneDigest, http.StatusOK)
	if _, err := database.GetVault(context.Background(), store.DefaultVault); err != nil {
		t.Fatalf("unmanaged default vault was pruned: %v", err)
	}
}

func setupFleetSQLStore(t *testing.T) (*store.SQLStore, string) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	defaultVault, err := database.GetVault(ctx, store.DefaultVault)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := database.RegisterFirstUser(ctx, "fleet-owner@example.com", []byte("hash"), []byte("salt"), defaultVault.ID, 1, 8192, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.CreateUserSession(ctx, store.CreateUserSessionParams{
		UserID: owner.ID, ExpiresAt: time.Now().Add(time.Hour), IdleTTL: time.Hour,
		DeviceLabel: "fleet-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	return database, session.ID
}

func cloneFleetManifest(t *testing.T, manifest *fleetconfig.Manifest) *fleetconfig.Manifest {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var cloned fleetconfig.Manifest
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return &cloned
}
