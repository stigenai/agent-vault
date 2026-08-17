package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		timeType := "TEXT"
		nowDefault := "datetime('now')"
		if db.Name() != "sqlite" {
			timeType = "TIMESTAMPTZ"
			nowDefault = "NOW()"
		}
		if err := db.Exec(`CREATE TABLE managed_resources (
			resource_kind TEXT NOT NULL CHECK(resource_kind IN ('vault','agent','grant','service','credential')),
			scope_id TEXT NOT NULL DEFAULT '',
			resource_id TEXT NOT NULL,
			manager TEXT NOT NULL,
			revision BIGINT NOT NULL CHECK(revision >= 1),
			created_at ` + timeType + ` NOT NULL DEFAULT (` + nowDefault + `),
			updated_at ` + timeType + ` NOT NULL DEFAULT (` + nowDefault + `),
			PRIMARY KEY (resource_kind, scope_id, resource_id)
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX idx_managed_resources_manager
			ON managed_resources(manager, resource_kind, scope_id)`).Error
	})
}
