package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var managedResourceManagerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

func validateManagedResource(key ManagedResourceKey, manager string, expectedRevision int64) error {
	if err := validateManagedResourceKey(key); err != nil {
		return err
	}
	if !managedResourceManagerPattern.MatchString(manager) {
		return fmt.Errorf("managed resource manager is invalid")
	}
	if expectedRevision < 0 {
		return fmt.Errorf("managed resource revision is invalid")
	}
	return nil
}

func validateManagedResourceKey(key ManagedResourceKey) error {
	switch key.Kind {
	case ManagedResourceVault, ManagedResourceAgent:
		if key.ScopeID != "" {
			return fmt.Errorf("instance managed resource must not have a scope")
		}
	case ManagedResourceGrant, ManagedResourceService, ManagedResourceCredential:
		if key.ScopeID == "" {
			return fmt.Errorf("scoped managed resource requires a scope")
		}
	default:
		return fmt.Errorf("managed resource kind is invalid")
	}
	if !safeManagedResourceID(key.ResourceID) || (key.ScopeID != "" && !safeManagedResourceID(key.ScopeID)) {
		return fmt.Errorf("managed resource identity is invalid")
	}
	return nil
}

func safeManagedResourceID(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *SQLStore) GetManagedResource(ctx context.Context, key ManagedResourceKey) (*ManagedResource, error) {
	if err := validateManagedResourceKey(key); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT resource_kind, scope_id, resource_id, manager,
		revision, created_at, updated_at FROM managed_resources
		WHERE resource_kind = ? AND scope_id = ? AND resource_id = ?`),
		key.Kind, key.ScopeID, key.ResourceID)
	return s.scanManagedResource(row)
}

func (s *SQLStore) ListManagedResources(ctx context.Context) ([]ManagedResource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT resource_kind, scope_id, resource_id, manager,
		revision, created_at, updated_at FROM managed_resources
		ORDER BY resource_kind, scope_id, resource_id`)
	if err != nil {
		return nil, fmt.Errorf("listing managed resources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result []ManagedResource
	for rows.Next() {
		resource, err := s.scanManagedResourceRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *resource)
	}
	return result, rows.Err()
}

// CompareAndSwapManagedResource atomically adopts an unmanaged resource when
// expectedRevision is zero, or advances a resource already owned by manager.
// It never transfers ownership between managers.
func (s *SQLStore) CompareAndSwapManagedResource(ctx context.Context, key ManagedResourceKey, manager string, expectedRevision int64) (*ManagedResource, error) {
	if err := validateManagedResource(key, manager, expectedRevision); err != nil {
		return nil, err
	}
	now := s.now()
	if expectedRevision == 0 {
		res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO managed_resources
			(resource_kind, scope_id, resource_id, manager, revision, created_at, updated_at)
			VALUES (?, ?, ?, ?, 1, ?, ?) ON CONFLICT(resource_kind, scope_id, resource_id) DO NOTHING`),
			key.Kind, key.ScopeID, key.ResourceID, manager, now, now)
		if err != nil {
			return nil, fmt.Errorf("adopting managed resource: %w", err)
		}
		if changed, _ := res.RowsAffected(); changed == 0 {
			return nil, s.managedResourceConflict(ctx, key, manager, expectedRevision)
		}
		return s.GetManagedResource(ctx, key)
	}

	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`UPDATE managed_resources
		SET revision = revision + 1, updated_at = ?
		WHERE resource_kind = ? AND scope_id = ? AND resource_id = ?
		AND manager = ? AND revision = ?`),
		now, key.Kind, key.ScopeID, key.ResourceID, manager, expectedRevision)
	if err != nil {
		return nil, fmt.Errorf("advancing managed resource: %w", err)
	}
	if changed, _ := res.RowsAffected(); changed == 0 {
		return nil, s.managedResourceConflict(ctx, key, manager, expectedRevision)
	}
	return s.GetManagedResource(ctx, key)
}

func (s *SQLStore) ReleaseManagedResource(ctx context.Context, key ManagedResourceKey, manager string, expectedRevision int64) error {
	if err := validateManagedResource(key, manager, expectedRevision); err != nil {
		return err
	}
	if expectedRevision == 0 {
		return s.managedResourceConflict(ctx, key, manager, expectedRevision)
	}
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM managed_resources
		WHERE resource_kind = ? AND scope_id = ? AND resource_id = ?
		AND manager = ? AND revision = ?`),
		key.Kind, key.ScopeID, key.ResourceID, manager, expectedRevision)
	if err != nil {
		return fmt.Errorf("releasing managed resource: %w", err)
	}
	if changed, _ := res.RowsAffected(); changed == 0 {
		return s.managedResourceConflict(ctx, key, manager, expectedRevision)
	}
	return nil
}

func (s *SQLStore) managedResourceConflict(ctx context.Context, key ManagedResourceKey, manager string, expectedRevision int64) error {
	actual, err := s.GetManagedResource(ctx, key)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("reading managed resource conflict: %w", err)
	}
	conflict := &ManagedResourceConflict{Key: key, ExpectedManager: manager, ExpectedRevision: expectedRevision}
	if actual != nil {
		conflict.ActualManager = actual.Manager
		conflict.ActualRevision = actual.Revision
	}
	return conflict
}

type managedResourceScanner interface {
	Scan(...any) error
}

func (s *SQLStore) scanManagedResource(scanner managedResourceScanner) (*ManagedResource, error) {
	var resource ManagedResource
	var createdAt, updatedAt any
	if err := scanner.Scan(&resource.Kind, &resource.ScopeID, &resource.ResourceID, &resource.Manager,
		&resource.Revision, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	var err error
	resource.CreatedAt, err = s.dialect.ScanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("scanning managed resource creation time: %w", err)
	}
	resource.UpdatedAt, err = s.dialect.ScanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("scanning managed resource update time: %w", err)
	}
	return &resource, nil
}

func (s *SQLStore) scanManagedResourceRow(rows *sql.Rows) (*ManagedResource, error) {
	return s.scanManagedResource(rows)
}
