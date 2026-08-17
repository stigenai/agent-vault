package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		blobType := "BLOB"
		timeType := "TEXT"
		nowDefault := "(datetime('now'))"
		if db.Dialector.Name() == "postgres" {
			blobType = "BYTEA"
			timeType = "TIMESTAMPTZ"
			nowDefault = "NOW()"
		}
		if err := db.Exec(`CREATE TABLE dek_wrappings (
id TEXT PRIMARY KEY,
master_key_id INTEGER NOT NULL DEFAULT 1 REFERENCES master_key(id) ON DELETE CASCADE,
provider TEXT NOT NULL,
key_id TEXT NOT NULL,
key_version TEXT NOT NULL DEFAULT '',
wrapped_dek ` + blobType + ` NOT NULL,
status TEXT NOT NULL CHECK (status IN ('primary', 'active', 'retired')),
verified_at ` + timeType + ` NOT NULL,
created_at ` + timeType + ` NOT NULL DEFAULT ` + nowDefault + `,
retired_at ` + timeType + `,
UNIQUE(master_key_id, provider, key_id, key_version)
)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE UNIQUE INDEX idx_dek_wrappings_one_primary
ON dek_wrappings(master_key_id) WHERE status = 'primary'`).Error
	})
}
