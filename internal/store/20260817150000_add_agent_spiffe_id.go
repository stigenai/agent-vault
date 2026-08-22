package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if !db.Migrator().HasColumn("agents", "spiffe_id") {
			if err := db.Exec("ALTER TABLE agents ADD COLUMN spiffe_id TEXT").Error; err != nil {
				return err
			}
		}
		return db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_spiffe_id ON agents(spiffe_id) WHERE spiffe_id IS NOT NULL").Error
	})
}
