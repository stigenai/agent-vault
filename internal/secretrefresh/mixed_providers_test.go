package secretrefresh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/config"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/awssecretsmanager"
	"github.com/Infisical/agent-vault/internal/secretprovider/onepasswordconnect"
	"github.com/Infisical/agent-vault/internal/secretprovider/openbaokv2"
	"github.com/Infisical/agent-vault/internal/secretrefresh"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsservice "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	awsSecret   = "LEAK-AWS-VALUE"
	baoSecret   = "LEAK-OPENBAO-VALUE"
	opSecret    = "LEAK-ONEPASSWORD-VALUE"
	infSecret   = "LEAK-INFISICAL-VALUE"
	localSecret = "LEAK-LOCAL-VALUE"
)

type integrationAWSClient struct{}

func (integrationAWSClient) GetSecretValue(context.Context, *awsservice.GetSecretValueInput, ...func(*awsservice.Options)) (*awsservice.GetSecretValueOutput, error) {
	return &awsservice.GetSecretValueOutput{
		SecretString: aws.String(awsSecret), VersionId: aws.String("aws-version-1"),
	}, nil
}

type integrationTokenSource struct{}

func (integrationTokenSource) Token(context.Context) ([]byte, error) {
	return []byte("EPHEMERAL-OPENBAO-TOKEN"), nil
}

type integrationInfisical struct{}

func (integrationInfisical) FetchSecret(_ context.Context, config infisical.VaultConfig, key string) (infisical.Secret, error) {
	if config.ProjectID != "project" || config.Environment != "prod" || config.SecretPath != "/" || key != "TOKEN" {
		return infisical.Secret{}, fmt.Errorf("unexpected non-secret reference")
	}
	return infisical.Secret{ID: "infisical-id", Key: key, Value: infSecret, Version: 1}, nil
}

func (integrationInfisical) AuthMethod() infisical.AuthMethod { return infisical.AuthKubernetes }

func TestMixedProviderVaultRefreshRedactionVersioningAndStaleness(t *testing.T) {
	ctx := context.Background()
	var baoMu sync.Mutex
	baoUnavailable := false
	baoServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		baoMu.Lock()
		unavailable := baoUnavailable
		baoMu.Unlock()
		if unavailable {
			http.Error(w, "LEAK-OPENBAO-UPSTREAM-ERROR", http.StatusServiceUnavailable)
			return
		}
		if request.URL.Path != "/v1/kv/data/application" || request.Header.Get("X-Vault-Token") != "EPHEMERAL-OPENBAO-TOKEN" {
			t.Errorf("OpenBao request = %s token=%q", request.URL.Path, request.Header.Get("X-Vault-Token"))
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"token":"` + baoSecret + `"},"metadata":{"deletion_time":"","destroyed":false,"version":1}}}`))
	}))
	defer baoServer.Close()
	opServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/vaults/vault/items/item" || request.Header.Get("Authorization") != "Bearer CONNECT-TOKEN" {
			t.Errorf("1Password request = %s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"version":1,"fields":[{"id":"password","label":"password","value":"` + opSecret + `"}]}`))
	}))
	defer opServer.Close()

	registry := secretprovider.NewRegistry()
	awsProvider, err := awssecretsmanager.New(ctx, awssecretsmanager.Options{Region: "us-east-1", Client: integrationAWSClient{}})
	if err != nil {
		t.Fatal(err)
	}
	baoProvider, err := openbaokv2.New(openbaokv2.Options{
		Address: baoServer.URL, TokenSource: integrationTokenSource{}, HTTPClient: baoServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenRef, err := config.ParseSecretRef("env://OP_CONNECT_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	opProvider, err := onepasswordconnect.New(onepasswordconnect.Options{
		Address: opServer.URL, TokenRef: tokenRef, HTTPClient: opServer.Client(),
		Resolver: config.Resolver{LookupEnv: func(string) (string, bool) { return "CONNECT-TOKEN", true }},
	})
	if err != nil {
		t.Fatal(err)
	}
	infProvider, err := infisical.NewProvider(infisical.ProviderOptions{Fetcher: integrationInfisical{}})
	if err != nil {
		t.Fatal(err)
	}
	for name, provider := range map[string]secretprovider.SecretProvider{
		"aws": awsProvider, "bao": baoProvider, "onepassword": opProvider, "infisical": infProvider,
	} {
		if err := registry.Register(name, provider); err != nil {
			t.Fatal(err)
		}
	}
	registry.Freeze()

	database, err := store.Open(filepath.Join(t.TempDir(), "mixed-providers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	vault, err := database.CreateVault(ctx, "mixed-provider-vault")
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{23}, 32)
	now := time.Now().UTC().Truncate(time.Second)
	setEncryptedCredential(t, database, vault.ID, "LOCAL", localSecret, dek)
	type sourceCase struct {
		key, kind, provider, reference, value string
	}
	cases := []sourceCase{
		{key: "AWS_TOKEN", kind: secretprovider.KindAWSSecretsManager, provider: "aws", reference: "application/prod", value: awsSecret},
		{key: "BAO_TOKEN", kind: secretprovider.KindOpenBaoKV2, provider: "bao", reference: "kv/application#token", value: baoSecret},
		{key: "OP_TOKEN", kind: secretprovider.KindOnePassword, provider: "onepassword", reference: "vault/item/password", value: opSecret},
		{key: "INF_TOKEN", kind: secretprovider.KindInfisical, provider: "infisical", reference: "project/prod#TOKEN", value: infSecret},
	}
	for _, test := range cases {
		setEncryptedCredential(t, database, vault.ID, test.key, "OLD-CACHE-"+test.key, dek)
		_, err := registry.ValidateAndSetSource(ctx, database, store.CredentialSource{
			VaultID: vault.ID, CredentialKey: test.key,
			Mode: store.CredentialSourceModeReference, Kind: test.kind,
			ProviderName: test.provider, Reference: test.reference,
			RefreshIntervalSeconds: 60, MaxStalenessSeconds: 180,
			Health: store.CredentialSourceHealthPending, NextRefreshAt: timePointer(now.Add(-time.Second)),
		})
		if err != nil {
			t.Fatalf("set source %s: %v", test.key, err)
		}
	}

	clock := now
	scheduler, err := secretrefresh.New(secretrefresh.Options{
		Store: database, Registry: registry, EncryptionKey: dek,
		WorkerID: "mixed-provider-replica", BatchSize: 20, ClaimLease: time.Minute,
		Now: func() time.Time { return clock }, Random: func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close()
	stats, err := scheduler.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Claimed != 4 || stats.Updated != 4 || stats.Failed != 0 {
		t.Fatalf("initial mixed refresh stats = %#v", stats)
	}
	assertCredentialValue(t, database, vault.ID, "LOCAL", localSecret, dek)
	for _, test := range cases {
		assertCredentialValue(t, database, vault.ID, test.key, test.value, dek)
	}
	assertNoSecretMetadata(t, database, vault.ID, stats)

	clock = now.Add(61 * time.Second)
	for _, test := range cases {
		source, err := database.GetCredentialSource(ctx, vault.ID, test.key)
		if err != nil {
			t.Fatal(err)
		}
		source.NextRefreshAt = timePointer(clock.Add(-time.Second))
		if _, err := database.SetCredentialSource(ctx, *source); err != nil {
			t.Fatal(err)
		}
	}
	stats, err = scheduler.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Unchanged != 4 || stats.Updated != 0 {
		t.Fatalf("unchanged provider versions stats = %#v", stats)
	}

	baoMu.Lock()
	baoUnavailable = true
	baoMu.Unlock()
	clock = now.Add(122 * time.Second)
	baoSource, err := database.GetCredentialSource(ctx, vault.ID, "BAO_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	baoSource.NextRefreshAt = timePointer(clock.Add(-time.Second))
	if _, err := database.SetCredentialSource(ctx, *baoSource); err != nil {
		t.Fatal(err)
	}
	stats, err = scheduler.RunOnce(ctx)
	if err != nil || stats.Failed != 1 {
		t.Fatalf("in-staleness outage stats = %#v, err=%v", stats, err)
	}
	baoSource, _ = database.GetCredentialSource(ctx, vault.ID, "BAO_TOKEN")
	if baoSource.Health != store.CredentialSourceHealthError || !store.CredentialSourceUsable(baoSource, clock) {
		t.Fatalf("last-known-good source = %#v", baoSource)
	}
	assertCredentialValue(t, database, vault.ID, "BAO_TOKEN", baoSecret, dek)

	clock = now.Add(301 * time.Second)
	baoSource.NextRefreshAt = timePointer(clock.Add(-time.Second))
	if _, err := database.SetCredentialSource(ctx, *baoSource); err != nil {
		t.Fatal(err)
	}
	stats, err = scheduler.RunOnce(ctx)
	if err != nil || stats.Failed != 1 {
		t.Fatalf("stale outage stats = %#v, err=%v", stats, err)
	}
	baoSource, _ = database.GetCredentialSource(ctx, vault.ID, "BAO_TOKEN")
	if baoSource.Health != store.CredentialSourceHealthStale || store.CredentialSourceUsable(baoSource, clock) || baoSource.LastErrorCode != string(secretprovider.CodeUnavailable) {
		t.Fatalf("stale source = %#v", baoSource)
	}
	assertNoSecretMetadata(t, database, vault.ID, stats)
}

func setEncryptedCredential(t *testing.T, database *store.SQLStore, vaultID, key, value string, dek []byte) {
	t.Helper()
	ciphertext, nonce, err := vaultcrypto.Encrypt([]byte(value), dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(value)) {
		t.Fatalf("ciphertext for %s contains plaintext", key)
	}
	if _, err := database.SetCredential(context.Background(), vaultID, key, ciphertext, nonce); err != nil {
		t.Fatal(err)
	}
}

func assertCredentialValue(t *testing.T, database *store.SQLStore, vaultID, key, expected string, dek []byte) {
	t.Helper()
	credential, err := database.GetCredential(context.Background(), vaultID, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(credential.Ciphertext, []byte(expected)) || bytes.Contains(credential.Nonce, []byte(expected)) {
		t.Fatalf("encrypted cache for %s contains plaintext", key)
	}
	plaintext, err := vaultcrypto.Decrypt(credential.Ciphertext, credential.Nonce, dek)
	if err != nil {
		t.Fatal(err)
	}
	defer vaultcrypto.WipeBytes(plaintext)
	if string(plaintext) != expected {
		t.Fatalf("credential %s = %q, want %q", key, plaintext, expected)
	}
}

func assertNoSecretMetadata(t *testing.T, database *store.SQLStore, vaultID string, stats secretrefresh.Stats) {
	t.Helper()
	sources, err := database.ListCredentialSources(context.Background(), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := json.Marshal(struct {
		Sources []store.CredentialSource `json:"sources"`
		Stats   secretrefresh.Stats      `json:"stats"`
	}{Sources: sources, Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{awsSecret, baoSecret, opSecret, infSecret, localSecret, "LEAK-OPENBAO-UPSTREAM-ERROR", "EPHEMERAL-OPENBAO-TOKEN", "CONNECT-TOKEN"} {
		if strings.Contains(string(diagnostic), secret) {
			t.Fatalf("metadata/API diagnostic leaked secret marker %q: %s", secret, diagnostic)
		}
	}
}

func timePointer(value time.Time) *time.Time { return &value }
