package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		timeType := "TEXT"
		if db.Name() == "postgres" {
			timeType = "TIMESTAMPTZ"
		}
		for _, statement := range []string{
			`ALTER TABLE credential_sources ADD COLUMN refresh_failures INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE credential_sources ADD COLUMN claim_owner TEXT`,
			`ALTER TABLE credential_sources ADD COLUMN claim_until ` + timeType,
			`CREATE INDEX idx_credential_sources_claim ON credential_sources(next_refresh_at, claim_until)`,
		} {
			if err := db.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
