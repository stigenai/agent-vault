package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		timeType := "TEXT"
		nowDefault := "(datetime('now'))"
		if db.Name() == "postgres" {
			timeType = "TIMESTAMPTZ"
			nowDefault = "NOW()"
		}
		return db.Exec(`CREATE TABLE key_recovery_events (
			id TEXT PRIMARY KEY,
			actor_id TEXT NOT NULL,
			actor_spiffe_id TEXT NOT NULL,
			recovery_wrapping_id TEXT NOT NULL,
			recovery_provider TEXT NOT NULL,
			recovery_key_id TEXT NOT NULL,
			new_primary_wrapping_id TEXT NOT NULL,
			new_primary_provider TEXT NOT NULL,
			new_primary_key_id TEXT NOT NULL,
			new_primary_key_version TEXT NOT NULL DEFAULT '',
			created_at ` + timeType + ` NOT NULL DEFAULT ` + nowDefault + `
		)`).Error
	})
}
