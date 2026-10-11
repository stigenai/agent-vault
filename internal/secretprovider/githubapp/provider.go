// Package githubapp mints GitHub App installation tokens on demand. The App's
// private key is never configured here: it is read from another configured
// secret provider on every mint and discarded, so no key is copied into Agent
// Vault. Minted tokens live only in memory until shortly before they expire.
package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
)

const (
	// DefaultAPIURL is the public GitHub API origin.
	DefaultAPIURL = "https://api.github.com"

	// FieldToken selects the raw installation token.
	FieldToken = "token"
	// FieldBasic selects base64("x-access-token:<token>") for git HTTP Basic auth.
	FieldBasic = "basic"

	// refreshMargin is how long before expires_at a cached token is replaced.
	refreshMargin = 10 * time.Minute
	basicUsername = "x-access-token"
)

var (
	appIDPattern          = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	installationIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// KeySource is the part of *secretprovider.Registry used to read the App's
// private key from another provider. It is resolved lazily so provider
// registration order does not matter.
type KeySource interface {
	Fetch(ctx context.Context, providerName, raw string) (secretprovider.Result, error)
}

type Options struct {
	AppID          string
	InstallationID string
	// APIURL defaults to DefaultAPIURL. GitHub Enterprise Server uses
	// https://<host>/api/v3.
	APIURL             string
	PrivateKeyProvider string
	PrivateKeyRef      string
	Keys               KeySource
	HTTPClient         *http.Client
	// Now is overridable for tests.
	Now func() time.Time
}

type Provider struct {
	appID               string
	tokenURL            string
	keyProvider, keyRef string
	keys                KeySource
	client              *http.Client
	now                 func() time.Time

	mu        sync.Mutex
	token     []byte
	expiresAt time.Time
}

// Reference selects which representation of the cached installation token to
// return. The grammar is exactly "token" or "basic".
type Reference struct{ field string }

func (r Reference) ProviderKind() string { return secretprovider.KindGitHubApp }
func (r Reference) Canonical() string    { return r.field }

func New(options Options) (*Provider, error) {
	if !appIDPattern.MatchString(options.AppID) {
		return nil, errors.New("GitHub App app_id is invalid")
	}
	if !installationIDPattern.MatchString(options.InstallationID) {
		return nil, errors.New("GitHub App installation_id must be numeric")
	}
	if options.PrivateKeyProvider == "" || options.PrivateKeyRef == "" || options.Keys == nil {
		return nil, errors.New("GitHub App private key provider and reference are required")
	}
	apiURL := options.APIURL
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	parsed, err := url.Parse(apiURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("GitHub App api_url must be an HTTPS URL without credentials")
	}
	client := options.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Provider{
		appID:       options.AppID,
		tokenURL:    strings.TrimRight(parsed.String(), "/") + "/app/installations/" + options.InstallationID + "/access_tokens",
		keyProvider: options.PrivateKeyProvider, keyRef: options.PrivateKeyRef,
		keys: options.Keys, client: client, now: now,
	}, nil
}

func (p *Provider) Kind() string { return secretprovider.KindGitHubApp }

func (p *Provider) ParseReference(raw string) (secretprovider.Reference, error) {
	if raw != FieldToken && raw != FieldBasic {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return Reference{field: raw}, nil
}

func (p *Provider) Fetch(ctx context.Context, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := ctx.Err(); err != nil {
		return secretprovider.Result{}, err
	}
	ref, ok := reference.(Reference)
	if !ok || (ref.field != FieldToken && ref.field != FieldBasic) {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	token, expiresAt, err := p.installationToken(ctx)
	if err != nil {
		return secretprovider.Result{}, err
	}
	defer vaultcrypto.WipeBytes(token)
	version := expiresAt.UTC().Format(time.RFC3339)
	if ref.field == FieldToken {
		return secretprovider.NewResult(token, version)
	}
	raw := append([]byte(basicUsername+":"), token...)
	defer vaultcrypto.WipeBytes(raw)
	basic := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(basic, raw)
	defer vaultcrypto.WipeBytes(basic)
	return secretprovider.NewResult(basic, version)
}

// installationToken returns a copy of the cached token, minting a new one when
// the cache is empty or within refreshMargin of expiry. The lock is held
// across the mint so concurrent callers share one request.
func (p *Provider) installationToken(ctx context.Context) ([]byte, time.Time, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.token) > 0 && p.now().Before(p.expiresAt.Add(-refreshMargin)) {
		return append([]byte(nil), p.token...), p.expiresAt, nil
	}
	token, expiresAt, err := p.mint(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	vaultcrypto.WipeBytes(p.token)
	p.token, p.expiresAt = token, expiresAt
	return append([]byte(nil), token...), expiresAt, nil
}

func (p *Provider) mint(ctx context.Context) ([]byte, time.Time, error) {
	jwt, err := p.signedJWT(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, nil)
	if err != nil {
		return nil, time.Time{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "agent-vault")
	resp, err := p.client.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, time.Time{}, ctxErr
		}
		return nil, time.Time{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, time.Time{}, statusError(resp.StatusCode)
	}
	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil ||
		body.Token == "" || !body.ExpiresAt.After(p.now()) {
		return nil, time.Time{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	return []byte(body.Token), body.ExpiresAt, nil
}

// signedJWT reads the private key from the chained provider, signs an RS256
// App JWT, and drops the key before returning.
func (p *Provider) signedJWT(ctx context.Context) (string, error) {
	result, err := p.keys.Fetch(ctx, p.keyProvider, p.keyRef)
	if err != nil {
		return "", chainError(err)
	}
	defer result.Wipe()
	key, err := parsePrivateKey(result.Bytes())
	if err != nil {
		return "", secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	now := p.now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": p.appID,
	})
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(string(pemBytes))))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	defer vaultcrypto.WipeBytes(block.Bytes)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return key, nil
}

// chainError keeps the chained provider's availability/authorization code but
// never reports its reference problems as this provider's reference problems.
func chainError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch code := secretprovider.CodeOf(err); code {
	case secretprovider.CodeInvalidReference, secretprovider.CodeProviderNotFound:
		return secretprovider.NewError(secretprovider.CodeUnavailable)
	default:
		return secretprovider.NewError(code)
	}
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return secretprovider.NewError(secretprovider.CodeAccessDenied)
	case http.StatusNotFound:
		return secretprovider.NewError(secretprovider.CodeNotFound)
	default:
		return secretprovider.NewError(secretprovider.CodeUnavailable)
	}
}
