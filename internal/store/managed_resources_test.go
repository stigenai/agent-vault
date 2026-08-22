package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestManagedResourceLifecycleAndConflicts(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	key := ManagedResourceKey{Kind: ManagedResourceService, ScopeID: "vault-id", ResourceID: "github-api"}

	if _, err := s.GetManagedResource(ctx, key); err != sql.ErrNoRows {
		t.Fatalf("unmanaged lookup = %v", err)
	}
	resource, err := s.CompareAndSwapManagedResource(ctx, key, "platform-fleet", 0)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Manager != "platform-fleet" || resource.Revision != 1 || resource.CreatedAt.IsZero() || resource.UpdatedAt.IsZero() {
		t.Fatalf("adopted resource = %#v", resource)
	}

	got, err := s.CompareAndSwapManagedResource(ctx, key, "other-manager", 1)
	assertManagedConflict(t, got, err, "other-manager", 1, "platform-fleet", 1)
	got, err = s.CompareAndSwapManagedResource(ctx, key, "platform-fleet", 0)
	assertManagedConflict(t, got, err, "platform-fleet", 0, "platform-fleet", 1)

	resource, err = s.CompareAndSwapManagedResource(ctx, key, "platform-fleet", 1)
	if err != nil || resource.Revision != 2 {
		t.Fatalf("advance = %#v, %v", resource, err)
	}
	if err := s.ReleaseManagedResource(ctx, key, "other-manager", 2); err == nil {
		t.Fatal("competing manager released resource")
	}
	if err := s.ReleaseManagedResource(ctx, key, "platform-fleet", 1); err == nil {
		t.Fatal("stale revision released resource")
	}
	if err := s.ReleaseManagedResource(ctx, key, "platform-fleet", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetManagedResource(ctx, key); err != sql.ErrNoRows {
		t.Fatalf("released lookup = %v", err)
	}

	_, err = s.CompareAndSwapManagedResource(ctx, key, "platform-fleet", 2)
	var conflict *ManagedResourceConflict
	if !errors.As(err, &conflict) || conflict.ActualManager != "" || conflict.ActualRevision != 0 {
		t.Fatalf("deleted conflict = %#v, %v", conflict, err)
	}
}

func TestManagedResourcesListIsDeterministic(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	keys := []ManagedResourceKey{
		{Kind: ManagedResourceService, ScopeID: "vault-z", ResourceID: "z-service"},
		{Kind: ManagedResourceAgent, ResourceID: "agent-id"},
		{Kind: ManagedResourceCredential, ScopeID: "vault-a", ResourceID: "TOKEN"},
	}
	for _, key := range keys {
		if _, err := s.CompareAndSwapManagedResource(ctx, key, "platform-fleet", 0); err != nil {
			t.Fatal(err)
		}
	}
	resources, err := s.ListManagedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 3 || resources[0].Kind != ManagedResourceAgent || resources[1].Kind != ManagedResourceCredential || resources[2].Kind != ManagedResourceService {
		t.Fatalf("resources = %#v", resources)
	}
}

func TestManagedResourceAdoptionIsAtomic(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	key := ManagedResourceKey{Kind: ManagedResourceVault, ResourceID: "vault-id"}
	var successes atomic.Int32
	var conflicts atomic.Int32
	var unexpected atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.CompareAndSwapManagedResource(ctx, key, "platform-fleet", 0)
			if err == nil {
				successes.Add(1)
				return
			}
			var conflict *ManagedResourceConflict
			if errors.As(err, &conflict) {
				conflicts.Add(1)
				return
			}
			unexpected.Store(err)
		}()
	}
	wg.Wait()
	if err, _ := unexpected.Load().(error); err != nil {
		t.Fatal(err)
	}
	if successes.Load() != 1 || conflicts.Load() != 15 {
		t.Fatalf("successes=%d conflicts=%d", successes.Load(), conflicts.Load())
	}
}

func TestManagedResourceValidation(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	tests := []struct {
		key      ManagedResourceKey
		manager  string
		revision int64
	}{
		{ManagedResourceKey{Kind: "unknown", ResourceID: "id"}, "manager", 0},
		{ManagedResourceKey{Kind: ManagedResourceVault, ScopeID: "scope", ResourceID: "id"}, "manager", 0},
		{ManagedResourceKey{Kind: ManagedResourceService, ResourceID: "id"}, "manager", 0},
		{ManagedResourceKey{Kind: ManagedResourceAgent, ResourceID: ""}, "manager", 0},
		{ManagedResourceKey{Kind: ManagedResourceAgent, ResourceID: "bad\nidentity"}, "manager", 0},
		{ManagedResourceKey{Kind: ManagedResourceAgent, ResourceID: "id"}, "manager with spaces", 0},
		{ManagedResourceKey{Kind: ManagedResourceAgent, ResourceID: "id"}, "manager", -1},
	}
	for _, test := range tests {
		if _, err := s.CompareAndSwapManagedResource(ctx, test.key, test.manager, test.revision); err == nil {
			t.Fatalf("invalid input accepted: %#v", test)
		}
	}
}

func assertManagedConflict(t *testing.T, _ *ManagedResource, err error, expectedManager string, expectedRevision int64, actualManager string, actualRevision int64) {
	t.Helper()
	var conflict *ManagedResourceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if conflict.ExpectedManager != expectedManager || conflict.ExpectedRevision != expectedRevision ||
		conflict.ActualManager != actualManager || conflict.ActualRevision != actualRevision {
		t.Fatalf("conflict = %#v", conflict)
	}
}
