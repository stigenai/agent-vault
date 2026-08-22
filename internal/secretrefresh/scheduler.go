// Package secretrefresh coordinates provider-backed credential refresh across
// replicas. Provider values exist in memory only long enough to encrypt them
// under the Agent Vault DEK.
package secretrefresh

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
)

type Options struct {
	Store         store.CredentialRefreshStore
	Registry      *secretprovider.Registry
	EncryptionKey []byte
	WorkerID      string
	ClaimLease    time.Duration
	BatchSize     int
	BaseBackoff   time.Duration
	MaxBackoff    time.Duration
	Jitter        float64
	Now           func() time.Time
	Random        func() float64
}

type Scheduler struct {
	store         store.CredentialRefreshStore
	registry      *secretprovider.Registry
	encryptionKey []byte
	workerID      string
	claimLease    time.Duration
	batchSize     int
	baseBackoff   time.Duration
	maxBackoff    time.Duration
	jitter        float64
	now           func() time.Time
	random        func() float64
}

type Stats struct {
	Claimed   int
	Updated   int
	Unchanged int
	Failed    int
	LostClaim int
}

func New(options Options) (*Scheduler, error) {
	if options.Store == nil || options.Registry == nil || len(options.EncryptionKey) != 32 || options.WorkerID == "" {
		return nil, fmt.Errorf("secret refresh store, registry, 32-byte key, and worker ID are required")
	}
	if options.ClaimLease == 0 {
		options.ClaimLease = 2 * time.Minute
	}
	if options.BatchSize == 0 {
		options.BatchSize = 25
	}
	if options.BaseBackoff == 0 {
		options.BaseBackoff = 5 * time.Second
	}
	if options.MaxBackoff == 0 {
		options.MaxBackoff = 15 * time.Minute
	}
	if options.Jitter == 0 {
		options.Jitter = 0.2
	}
	if options.ClaimLease < 5*time.Second || options.ClaimLease > 10*time.Minute ||
		options.BatchSize < 1 || options.BatchSize > 100 || options.BaseBackoff <= 0 ||
		options.MaxBackoff < options.BaseBackoff || options.Jitter < 0 || options.Jitter > 0.5 {
		return nil, fmt.Errorf("secret refresh timing options are invalid")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Float64
	}
	return &Scheduler{
		store: options.Store, registry: options.Registry,
		encryptionKey: append([]byte(nil), options.EncryptionKey...), workerID: options.WorkerID,
		claimLease: options.ClaimLease, batchSize: options.BatchSize,
		baseBackoff: options.BaseBackoff, maxBackoff: options.MaxBackoff,
		jitter: options.Jitter, now: options.Now, random: options.Random,
	}, nil
}

func (s *Scheduler) Close() {
	if s == nil {
		return
	}
	vaultcrypto.WipeBytes(s.encryptionKey)
	s.encryptionKey = nil
}

func (s *Scheduler) RunOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	now := s.now().UTC()
	sources, err := s.store.ClaimCredentialSources(ctx, s.workerID, now, s.claimLease, s.batchSize)
	if err != nil {
		return stats, err
	}
	stats.Claimed = len(sources)
	for i := range sources {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		outcome, err := s.refreshOne(ctx, &sources[i], now)
		if err != nil {
			return stats, err
		}
		switch outcome {
		case "updated":
			stats.Updated++
		case "unchanged":
			stats.Unchanged++
		case "failed":
			stats.Failed++
		case "lost":
			stats.LostClaim++
		}
	}
	return stats, nil
}

// Run polls for due work until cancellation. Provider failures are persisted
// by RunOnce and do not surface here; callback receives only scheduler/store
// errors and per-cycle non-secret counters.
func (s *Scheduler) Run(ctx context.Context, pollInterval time.Duration, callback func(Stats, error)) error {
	if pollInterval < time.Second || pollInterval > time.Minute {
		return fmt.Errorf("secret refresh poll interval must be between one second and one minute")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			stats, err := s.RunOnce(ctx)
			if callback != nil {
				callback(stats, err)
			}
			timer.Reset(pollInterval)
		}
	}
}

func (s *Scheduler) refreshOne(ctx context.Context, source *store.CredentialSource, now time.Time) (string, error) {
	result, err := s.registry.Fetch(ctx, source.ProviderName, source.Reference)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		health := store.CredentialSourceHealthStale
		if store.CredentialSourceUsable(source, now) {
			health = store.CredentialSourceHealthError
		}
		applied, storeErr := s.store.FailCredentialRefresh(ctx, store.CredentialRefreshFailure{
			VaultID: source.VaultID, CredentialKey: source.CredentialKey, ClaimOwner: s.workerID,
			ErrorCode: string(secretprovider.CodeOf(err)), Health: health, AttemptedAt: now,
			NextRefreshAt: now.Add(s.backoff(source.RefreshFailures)),
		})
		if storeErr != nil {
			return "", storeErr
		}
		if !applied {
			return "lost", nil
		}
		return "failed", nil
	}
	defer result.Wipe()
	changed := result.Version() == "" || result.Version() != source.ProviderVersion || source.CacheUpdatedAt == nil
	completion := store.CredentialRefreshCompletion{
		VaultID: source.VaultID, CredentialKey: source.CredentialKey, ClaimOwner: s.workerID,
		ProviderVersion: result.Version(), ValueChanged: changed, RefreshedAt: now,
		NextRefreshAt: now.Add(s.withJitter(time.Duration(source.RefreshIntervalSeconds) * time.Second)),
	}
	if changed {
		ciphertext, nonce, err := vaultcrypto.Encrypt(result.Bytes(), s.encryptionKey)
		if err != nil {
			return "", fmt.Errorf("encrypt refreshed credential cache: %w", err)
		}
		completion.Ciphertext = ciphertext
		completion.Nonce = nonce
	}
	applied, err := s.store.CompleteCredentialRefresh(ctx, completion)
	if err != nil {
		return "", err
	}
	if !applied {
		return "lost", nil
	}
	if changed {
		return "updated", nil
	}
	return "unchanged", nil
}

func (s *Scheduler) backoff(previousFailures int) time.Duration {
	exponent := math.Min(float64(previousFailures), 20)
	duration := time.Duration(float64(s.baseBackoff) * math.Pow(2, exponent))
	if duration > s.maxBackoff || duration < 0 {
		duration = s.maxBackoff
	}
	return s.withJitter(duration)
}

func (s *Scheduler) withJitter(duration time.Duration) time.Duration {
	factor := 1 + ((s.random()*2)-1)*s.jitter
	result := time.Duration(float64(duration) * factor)
	if result < time.Second {
		return time.Second
	}
	return result
}
