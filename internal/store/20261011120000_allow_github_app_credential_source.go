package store

import "gorm.io/gorm"

const credentialSourceKinds = `'aws-secrets-manager','openbao-kv-v2','onepassword-connect','infisical','spiffe-jwt-svid','github-app'`

// Widens credential_sources.kind to admit github-app. The list must hold every
// kind that an earlier migration admitted, such as spiffe-jwt-svid. Postgres swaps the
// CHECK constraint; SQLite cannot alter one, so the table is rebuilt.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() == "postgres" {
			for _, statement := range []string{
				`ALTER TABLE credential_sources DROP CONSTRAINT IF EXISTS credential_sources_kind_check`,
				`ALTER TABLE credential_sources ADD CONSTRAINT credential_sources_kind_check CHECK(kind IN (` + credentialSourceKinds + `))`,
			} {
				if err := db.Exec(statement).Error; err != nil {
					return err
				}
			}
			return nil
		}
		for _, statement := range []string{
			`CREATE TABLE credential_sources_new (
				vault_id TEXT NOT NULL,
				credential_key TEXT NOT NULL,
				mode TEXT NOT NULL CHECK(mode IN ('reference')),
				kind TEXT NOT NULL CHECK(kind IN (` + credentialSourceKinds + `)),
				provider_name TEXT NOT NULL,
				reference TEXT NOT NULL,
				refresh_interval_seconds INTEGER NOT NULL CHECK(refresh_interval_seconds >= 10),
				max_staleness_seconds INTEGER NOT NULL CHECK(max_staleness_seconds >= 0),
				provider_version TEXT NOT NULL DEFAULT '',
				health TEXT NOT NULL CHECK(health IN ('pending','ok','error','stale')),
				last_error_code TEXT NOT NULL DEFAULT '',
				cache_updated_at TEXT,
				last_refresh_at TEXT,
				last_success_at TEXT,
				next_refresh_at TEXT,
				created_at TEXT NOT NULL DEFAULT (datetime('now')),
				updated_at TEXT NOT NULL DEFAULT (datetime('now')),
				refresh_failures INTEGER NOT NULL DEFAULT 0,
				claim_owner TEXT,
				claim_until TEXT,
				PRIMARY KEY (vault_id, credential_key),
				FOREIGN KEY (vault_id, credential_key) REFERENCES credentials(vault_id, key) ON DELETE CASCADE
			)`,
			`INSERT INTO credential_sources_new SELECT
				vault_id, credential_key, mode, kind, provider_name, reference,
				refresh_interval_seconds, max_staleness_seconds, provider_version,
				health, last_error_code, cache_updated_at, last_refresh_at,
				last_success_at, next_refresh_at, created_at, updated_at,
				refresh_failures, claim_owner, claim_until
			FROM credential_sources`,
			`DROP TABLE credential_sources`,
			`ALTER TABLE credential_sources_new RENAME TO credential_sources`,
			`CREATE INDEX idx_credential_sources_refresh ON credential_sources(health, next_refresh_at)`,
			`CREATE INDEX idx_credential_sources_claim ON credential_sources(next_refresh_at, claim_until)`,
		} {
			if err := db.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
