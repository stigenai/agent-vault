package requestlog

import (
	"context"
	"testing"
	"time"
)

type retentionConfigStore struct{ setting string }

func (s retentionConfigStore) GetSetting(context.Context, string) (string, error) {
	return s.setting, nil
}
func (retentionConfigStore) DeleteOldRequestLogs(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (retentionConfigStore) TrimRequestLogsToCap(context.Context, string, int64) (int64, error) {
	return 0, nil
}
func (retentionConfigStore) VaultIDsWithLogs(context.Context) ([]string, error) { return nil, nil }

func TestResolveRetentionConfiguredHonorsLockAndSetting(t *testing.T) {
	base := RetentionConfig{MaxAge: 24 * time.Hour, MaxRowsPerVault: 100, Tick: time.Minute}
	store := retentionConfigStore{setting: `{"max_age_hours":48,"max_rows_per_vault":200}`}

	got := ResolveRetentionConfigured(context.Background(), store, base, false)
	if got.MaxAge != 48*time.Hour || got.MaxRowsPerVault != 200 {
		t.Fatalf("unlocked config = %#v", got)
	}
	got = ResolveRetentionConfigured(context.Background(), store, base, true)
	if got != base {
		t.Fatalf("locked config = %#v, want %#v", got, base)
	}
}
