package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/Infisical/agent-vault/internal/auth"
	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/keywrap/agerecovery"
	"github.com/Infisical/agent-vault/internal/keywrap/awskms"
	"github.com/Infisical/agent-vault/internal/keywrap/openbao"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func unlockOrSetupWithConfiguredWrappers(
	cmd *cobra.Command,
	db store.Store,
	passwordStdin bool,
	encryption runtimeconfig.Encryption,
	identitySource *workloadidentity.Source,
	authTrustDomains []string,
) (*auth.MasterKey, error) {
	if len(encryption.Wrappers) == 0 {
		return unlockOrSetup(cmd, db, passwordStdin, encryption.LegacyMasterPassword)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	wrappers, err := buildConfiguredWrappers(ctx, encryption.Wrappers, identitySource, authTrustDomains)
	if err != nil {
		return nil, err
	}
	return unlockOrSetupWithWrapperSet(cmd, db, passwordStdin, encryption, wrappers)
}

func unlockOrSetupWithWrapperSet(cmd *cobra.Command, db store.Store, passwordStdin bool, encryption runtimeconfig.Encryption, wrappers map[string]keywrap.KeyWrapper) (*auth.MasterKey, error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	persistence, ok := db.(store.KeyWrappingStore)
	if !ok {
		return nil, errors.New("configured DEK wrappers require wrapping-capable storage")
	}
	primaryWrapper := wrappers[encryption.PrimaryWrapper]
	if primaryWrapper == nil {
		return nil, errors.New("configured primary DEK wrapper is unavailable")
	}
	binding, err := keywrap.EnsureInstanceBinding(ctx, persistence)
	if err != nil {
		return nil, err
	}
	persistedPrimary, err := persistence.GetPrimaryDEKWrapping(ctx)
	if err == nil {
		// Once a provider primary exists, provider failure is fatal. Never
		// downgrade to legacy password/plaintext or recovery automatically.
		currentWrapper := wrapperForIdentity(wrappers, persistedPrimary.Provider, persistedPrimary.KeyID)
		if currentWrapper == nil {
			return nil, fmt.Errorf("persisted primary DEK wrapper %s/%s is not configured", persistedPrimary.Provider, persistedPrimary.KeyID)
		}
		dek, err := keywrap.UnwrapRecord(ctx, persistedPrimary, currentWrapper, binding)
		if err != nil {
			return nil, fmt.Errorf("unwrap configured primary DEK: %w", err)
		}
		defer vaultcrypto.WipeBytes(dek)
		record, err := db.GetMasterKeyRecord(ctx)
		if err != nil {
			return nil, err
		}
		masterKey, err := auth.UnlockWithDEK(dek, buildVerificationRecord(record))
		if err != nil {
			return nil, err
		}
		if currentWrapper.Identity() != primaryWrapper.Identity() {
			if _, err := keywrap.EnsurePrimary(ctx, persistence, primaryWrapper, masterKey.Key(), binding); err != nil {
				masterKey.Wipe()
				return nil, fmt.Errorf("rotate DEK to configured primary wrapper: %w", err)
			}
		}
		return masterKey, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	masterKey, err := unlockOrSetup(cmd, db, passwordStdin, encryption.LegacyMasterPassword)
	if err != nil {
		return nil, err
	}
	if _, err := keywrap.EnsurePrimary(ctx, persistence, primaryWrapper, masterKey.Key(), binding); err != nil {
		masterKey.Wipe()
		return nil, fmt.Errorf("migrate DEK to configured primary wrapper: %w", err)
	}
	for name, wrapper := range wrappers {
		if name == encryption.PrimaryWrapper {
			continue
		}
		if _, err := keywrap.EnsureAdditional(ctx, persistence, wrapper, masterKey.Key(), binding); err != nil {
			masterKey.Wipe()
			return nil, fmt.Errorf("add DEK wrapping %q: %w", name, err)
		}
	}
	return masterKey, nil
}

func wrapperForIdentity(wrappers map[string]keywrap.KeyWrapper, provider, keyID string) keywrap.KeyWrapper {
	for _, wrapper := range wrappers {
		identity := wrapper.Identity()
		if identity.Provider == provider && identity.KeyID == keyID {
			return wrapper
		}
	}
	return nil
}

func buildConfiguredWrappers(ctx context.Context, configs []runtimeconfig.KeyWrapperConfig, identitySource *workloadidentity.Source, authTrustDomains []string) (map[string]keywrap.KeyWrapper, error) {
	result := make(map[string]keywrap.KeyWrapper, len(configs))
	for _, config := range configs {
		switch config.Kind {
		case "aws-kms":
			wrapper, err := awskms.New(ctx, awskms.Options{KeyARN: config.AWSKMS.KeyARN, Region: config.AWSKMS.Region})
			if err != nil {
				return nil, fmt.Errorf("configure DEK wrapper %q: %w", config.Name, err)
			}
			result[config.Name] = wrapper
		case "openbao-transit":
			if identitySource == nil {
				return nil, fmt.Errorf("configure DEK wrapper %q: SPIFFE workload identity is required", config.Name)
			}
			domains := make([]spiffeid.TrustDomain, 0)
			// OpenBao is expected in the same explicitly configured trust
			// domains as the Agent Vault listener.
			for _, raw := range authTrustDomains {
				domain, err := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
				if err != nil {
					return nil, fmt.Errorf("configure DEK wrapper %q: invalid trust domain", config.Name)
				}
				domains = append(domains, domain)
			}
			tokens, err := openbao.NewX509TokenSource(openbao.X509Options{
				Address: config.OpenBao.Address, AuthMount: config.OpenBao.AuthMount,
				Role: config.OpenBao.Role, Source: identitySource, TrustDomains: domains,
			})
			if err != nil {
				return nil, fmt.Errorf("configure DEK wrapper %q: %w", config.Name, err)
			}
			wrapper, err := openbao.New(openbao.Options{
				Address: config.OpenBao.Address, Mount: config.OpenBao.Mount,
				KeyName: config.OpenBao.KeyName, TokenSource: tokens,
			})
			if err != nil {
				return nil, fmt.Errorf("configure DEK wrapper %q: %w", config.Name, err)
			}
			result[config.Name] = wrapper
		case "age-x25519":
			wrapper, err := agerecovery.New(config.Age.Recipient)
			if err != nil {
				return nil, fmt.Errorf("configure DEK wrapper %q: %w", config.Name, err)
			}
			result[config.Name] = wrapper
		}
	}
	return result, nil
}
