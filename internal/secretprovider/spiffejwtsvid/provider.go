// Package spiffejwtsvid mints JWT-SVIDs from the SPIFFE Workload API. The
// token is the credential value, so it is short-lived and never leaves this
// package except as an owned secretprovider.Result.
//
// Freshness contract: every token returned by Fetch has at least
// store.MaxSPIFFEJWTSVIDStalenessSeconds of lifetime left at return time. The
// store caps max_staleness for this kind at the same value, so a cached copy
// can never outlive the token it holds.
package spiffejwtsvid

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxAudiences = 8

// minRemaining is the lifetime every returned token must still have.
const minRemaining = time.Duration(store.MaxSPIFFEJWTSVIDStalenessSeconds) * time.Second

// Source is the Workload API seam. *workloadapi.Client satisfies it.
type Source interface {
	FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error)
}

type Options struct {
	// Source overrides the Workload API client (tests).
	Source Source
	// Address is the Workload API address, for example unix:///run/spire/sockets/agent.sock.
	// Empty means SPIFFE_ENDPOINT_SOCKET.
	Address string
	Now     func() time.Time
}

type Provider struct {
	source Source
	closer func() error
	now    func() time.Time

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	token   []byte
	expiry  time.Time
	refresh time.Time // fetch a new token at or after this time
}

// Reference grammar:
//
//	spiffe://<trust-domain>/<path>?audience=<aud>[&audience=<aud>...]
//
// The SPIFFE ID is the subject requested from the Workload API. The first
// audience is the primary audience; further ones are extra audiences.
type Reference struct {
	subject   spiffeid.ID
	audiences []string
	canonical string
}

func (r Reference) ProviderKind() string { return secretprovider.KindSPIFFEJWTSVID }
func (r Reference) Canonical() string    { return r.canonical }

// New connects to the Workload API (lazily; the dial happens on first fetch)
// unless options.Source is set. Close releases the client.
func New(ctx context.Context, options Options) (*Provider, error) {
	p := &Provider{source: options.Source, now: options.Now, cache: map[string]*entry{}}
	if p.now == nil {
		p.now = time.Now
	}
	if p.source == nil {
		var clientOptions []workloadapi.ClientOption
		if options.Address != "" {
			clientOptions = append(clientOptions, workloadapi.WithAddr(options.Address))
		}
		client, err := workloadapi.New(ctx, clientOptions...)
		if err != nil {
			return nil, errors.New("SPIFFE Workload API client is unavailable")
		}
		p.source = client
		p.closer = client.Close
	}
	return p, nil
}

func (p *Provider) Kind() string { return secretprovider.KindSPIFFEJWTSVID }

func (p *Provider) ParseReference(raw string) (secretprovider.Reference, error) {
	ref, err := parseReference(raw)
	if err != nil {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return ref, nil
}

func parseReference(raw string) (Reference, error) {
	var result Reference
	if strings.Contains(raw, "#") {
		return result, errors.New("fragments are not allowed")
	}
	idPart, query, _ := strings.Cut(raw, "?")
	subject, err := spiffeid.FromString(idPart)
	if err != nil || subject.Path() == "" {
		return result, errors.New("a SPIFFE ID with a path is required")
	}
	values, err := url.ParseQuery(query)
	if err != nil || len(values) != 1 {
		return result, errors.New("only audience parameters are allowed")
	}
	audiences := values["audience"]
	if len(audiences) == 0 || len(audiences) > maxAudiences {
		return result, errors.New("one to eight audiences are required")
	}
	for _, aud := range audiences {
		if aud == "" || len(aud) > 256 || strings.TrimSpace(aud) != aud {
			return result, errors.New("invalid audience")
		}
	}
	result.subject = subject
	result.audiences = append([]string(nil), audiences...)
	parts := make([]string, len(audiences))
	for i, aud := range audiences {
		parts[i] = "audience=" + url.QueryEscape(aud)
	}
	result.canonical = subject.String() + "?" + strings.Join(parts, "&")
	return result, nil
}

func (p *Provider) Fetch(ctx context.Context, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := ctx.Err(); err != nil {
		return secretprovider.Result{}, err
	}
	ref, ok := reference.(Reference)
	if !ok || ref.subject.IsZero() || len(ref.audiences) == 0 {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if cached := p.cache[ref.canonical]; cached != nil && now.Before(cached.refresh) {
		return result(cached)
	}
	svid, err := p.source.FetchJWTSVID(ctx, jwtsvid.Params{
		Subject: ref.subject, Audience: ref.audiences[0], ExtraAudiences: ref.audiences[1:],
	})
	if err != nil {
		return secretprovider.Result{}, mapError(ctx, err)
	}
	if svid == nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	token := []byte(svid.Marshal())
	lifetime := svid.Expiry.Sub(now)
	if len(token) == 0 {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	if lifetime <= minRemaining {
		// The agent handed back a token about to expire; retry later.
		vaultcrypto.WipeBytes(token)
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	// Refresh with a third of the lifetime left, never later than minRemaining
	// before expiry, so a returned token always has minRemaining to live.
	margin := lifetime / 3
	if margin < minRemaining {
		margin = minRemaining
	}
	fresh := &entry{token: token, expiry: svid.Expiry, refresh: svid.Expiry.Add(-margin)}
	if old := p.cache[ref.canonical]; old != nil {
		vaultcrypto.WipeBytes(old.token)
	}
	p.cache[ref.canonical] = fresh
	return result(fresh)
}

func result(e *entry) (secretprovider.Result, error) {
	return secretprovider.NewResult(e.token, strconv.FormatInt(e.expiry.Unix(), 10))
}

// Close wipes cached tokens and closes the Workload API client.
func (p *Provider) Close() error {
	p.mu.Lock()
	for key, e := range p.cache {
		vaultcrypto.WipeBytes(e.token)
		delete(p.cache, key)
	}
	p.mu.Unlock()
	if p.closer != nil {
		return p.closer()
	}
	return nil
}

func mapError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		return secretprovider.NewError(secretprovider.CodeAccessDenied)
	case codes.NotFound:
		return secretprovider.NewError(secretprovider.CodeNotFound)
	case codes.InvalidArgument:
		return secretprovider.NewError(secretprovider.CodeInvalidReference)
	default:
		return secretprovider.NewError(secretprovider.CodeUnavailable)
	}
}
