package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/openbaoauth"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/awssecretsmanager"
	"github.com/Infisical/agent-vault/internal/secretprovider/onepasswordconnect"
	"github.com/Infisical/agent-vault/internal/secretprovider/openbaokv2"
	"github.com/Infisical/agent-vault/internal/secretrefresh"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func attachSecretProviders(srv *server.Server, cfg runtimeconfig.Runtime, dek []byte, database store.Store, logger *slog.Logger, identity *workloadidentity.Source, infisicalClient *infisical.Client) (returnErr error) {
	if len(cfg.SecretProviders) == 0 && infisicalClient == nil {
		return nil
	}
	refreshStore, ok := database.(store.CredentialRefreshStore)
	if !ok {
		return fmt.Errorf("store does not support credential refresh coordination")
	}
	registry := secretprovider.NewRegistry()
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStartup()
	var ownedJWT []*workloadapi.JWTSource
	defer func() {
		if returnErr != nil {
			for _, source := range ownedJWT {
				_ = source.Close()
			}
		}
	}()

	for _, configured := range cfg.SecretProviders {
		var provider secretprovider.SecretProvider
		var err error
		switch configured.Kind {
		case secretprovider.KindAWSSecretsManager:
			provider, err = awssecretsmanager.New(startupCtx, awssecretsmanager.Options{Region: configured.Region})
		case secretprovider.KindOpenBaoKV2:
			var tokens openbaoauth.TokenSource
			switch configured.Auth {
			case "spiffe-x509":
				if identity == nil {
					return fmt.Errorf("secret provider %q requires SPIFFE X.509 identity", configured.Name)
				}
				rawDomains := configured.TrustDomains
				if len(rawDomains) == 0 {
					rawDomains = cfg.Auth.TrustDomains
				}
				domains := make([]spiffeid.TrustDomain, 0, len(rawDomains))
				for _, raw := range rawDomains {
					domain, parseErr := spiffeid.TrustDomainFromString(strings.TrimPrefix(raw, "spiffe://"))
					if parseErr != nil {
						return fmt.Errorf("secret provider %q trust domain is invalid", configured.Name)
					}
					domains = append(domains, domain)
				}
				tokens, err = openbaoauth.NewX509TokenSource(openbaoauth.X509Options{
					Address: configured.Address, AuthMount: configured.AuthMount, Role: configured.Role,
					Source: identity, TrustDomains: domains,
				})
			case "spiffe-jwt":
				jwtSource, sourceErr := workloadapi.NewJWTSource(startupCtx,
					workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.Auth.WorkloadAPI)))
				if sourceErr != nil {
					return fmt.Errorf("secret provider %q JWT-SVID source unavailable", configured.Name)
				}
				ownedJWT = append(ownedJWT, jwtSource)
				tokens, err = openbaoauth.NewJWTTokenSource(openbaoauth.JWTOptions{
					Address: configured.Address, AuthMount: configured.AuthMount, Role: configured.Role,
					Audience: configured.Audience, Source: jwtSource,
				})
			}
			if err == nil {
				provider, err = openbaokv2.New(openbaokv2.Options{Address: configured.Address, TokenSource: tokens})
			}
		case secretprovider.KindOnePassword:
			provider, err = onepasswordconnect.New(onepasswordconnect.Options{
				Address: configured.Address, TokenRef: configured.Token, Resolver: runtimeconfig.Resolver{},
			})
		case secretprovider.KindInfisical:
			if infisicalClient == nil {
				return fmt.Errorf("secret provider %q requires configured Infisical machine identity", configured.Name)
			}
			provider, err = infisical.NewProvider(infisical.ProviderOptions{Fetcher: infisicalClient})
		}
		if err != nil {
			return fmt.Errorf("initialize secret provider %q: %w", configured.Name, err)
		}
		if err := registry.Register(configured.Name, provider); err != nil {
			return err
		}
	}

	if infisicalClient != nil {
		legacyStore, ok := database.(infisical.LegacyProviderStore)
		if !ok {
			return fmt.Errorf("store does not support legacy Infisical discovery")
		}
		if err := infisical.RegisterLegacyProviders(startupCtx, registry, legacyStore, infisicalClient); err != nil {
			return err
		}
	}
	registry.Freeze()
	workerID := secretRefreshWorkerID()
	scheduler, err := secretrefresh.New(secretrefresh.Options{
		Store: refreshStore, Registry: registry, EncryptionKey: dek, WorkerID: workerID,
		ClaimLease: 2 * time.Minute, BatchSize: 25,
	})
	if err != nil {
		return err
	}
	srv.AttachSecretRefreshScheduler(scheduler)
	for _, source := range ownedJWT {
		srv.AttachSecretProviderCloser(source)
	}
	logger.Info("secret provider refresh configured", slog.Int("providers", len(registry.Names())))
	return nil
}

func secretRefreshWorkerID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "agent-vault"
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return hostname + "-worker"
	}
	return hostname + "-" + hex.EncodeToString(random)
}
