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
		if err := db.Exec(`CREATE TABLE credential_sources (
			vault_id TEXT NOT NULL,
			credential_key TEXT NOT NULL,
			mode TEXT NOT NULL CHECK(mode IN ('reference')),
			kind TEXT NOT NULL CHECK(kind IN ('aws-secrets-manager','openbao-kv-v2','onepassword-connect','infisical')),
			provider_name TEXT NOT NULL,
			reference TEXT NOT NULL,
			refresh_interval_seconds INTEGER NOT NULL CHECK(refresh_interval_seconds >= 10),
			max_staleness_seconds INTEGER NOT NULL CHECK(max_staleness_seconds >= 0),
			provider_version TEXT NOT NULL DEFAULT '',
			health TEXT NOT NULL CHECK(health IN ('pending','ok','error','stale')),
			last_error_code TEXT NOT NULL DEFAULT '',
			cache_updated_at ` + timeType + `,
			last_refresh_at ` + timeType + `,
			last_success_at ` + timeType + `,
			next_refresh_at ` + timeType + `,
			created_at ` + timeType + ` NOT NULL DEFAULT ` + nowDefault + `,
			updated_at ` + timeType + ` NOT NULL DEFAULT ` + nowDefault + `,
			PRIMARY KEY (vault_id, credential_key),
			FOREIGN KEY (vault_id, credential_key) REFERENCES credentials(vault_id, key) ON DELETE CASCADE
		)`).Error; err != nil {
			return err
		}
		if err := db.Exec(`CREATE INDEX idx_credential_sources_refresh
			ON credential_sources(health, next_refresh_at)`).Error; err != nil {
			return err
		}
		// Preserve existing Infisical snapshots as encrypted caches and attach
		// per-credential compatibility references. Existing error text is not
		// copied because it may contain upstream payloads.
		return db.Exec(`INSERT INTO credential_sources (
			vault_id, credential_key, mode, kind, provider_name, reference,
			refresh_interval_seconds, max_staleness_seconds, provider_version,
			health, last_error_code, cache_updated_at, last_refresh_at,
			last_success_at, next_refresh_at, created_at, updated_at)
		SELECT c.vault_id, c.key, 'reference', 'infisical',
			'legacy-infisical-' || c.vault_id, c.key,
			vcs.poll_interval_seconds, 0, '',
			CASE vcs.last_sync_status WHEN 'ok' THEN 'ok' WHEN 'error' THEN 'error' ELSE 'pending' END,
			CASE vcs.last_sync_status WHEN 'error' THEN 'legacy-sync-error' ELSE '' END,
			c.updated_at, vcs.last_synced_at,
			CASE WHEN vcs.last_sync_status = 'ok' THEN COALESCE(vcs.last_synced_at, c.updated_at) ELSE c.updated_at END,
			NULL, c.created_at, c.updated_at
		FROM credentials c
		JOIN vault_credential_stores vcs ON vcs.vault_id = c.vault_id
		WHERE c.type = 'static'
		ON CONFLICT(vault_id, credential_key) DO NOTHING`).Error
	})
}
