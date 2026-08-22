// Package openbaokv2 resolves credential values from OpenBao KV version 2.
package openbaokv2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/openbaoauth"
	"github.com/Infisical/agent-vault/internal/secretprovider"
)

type Options struct {
	Address     string
	TokenSource openbaoauth.TokenSource
	HTTPClient  *http.Client
}

type Provider struct {
	address string
	tokens  openbaoauth.TokenSource
	client  *http.Client
}

// Reference grammar:
//
//	mount/path[?version=N]#field
//
// Mount is one OpenBao mount segment, path may contain multiple segments,
// and field is one top-level key in the KV v2 data object.
type Reference struct {
	mount     string
	path      string
	field     string
	version   uint64
	canonical string
}

func (r Reference) ProviderKind() string { return secretprovider.KindOpenBaoKV2 }
func (r Reference) Canonical() string    { return r.canonical }

var (
	pathSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	fieldPattern       = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,256}$`)
)

func New(options Options) (*Provider, error) {
	address, err := validateAddress(options.Address)
	if err != nil {
		return nil, err
	}
	if options.TokenSource == nil {
		return nil, errors.New("OpenBao token source is required")
	}
	client := options.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport}
	}
	return &Provider{address: address, tokens: options.TokenSource, client: client}, nil
}

func (p *Provider) Kind() string { return secretprovider.KindOpenBaoKV2 }

func (p *Provider) ParseReference(raw string) (secretprovider.Reference, error) {
	if p == nil || p.client == nil || p.tokens == nil {
		return nil, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	ref, err := parseReference(raw)
	if err != nil {
		return nil, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	return ref, nil
}

func parseReference(raw string) (Reference, error) {
	var result Reference
	base, rawField, hasField := strings.Cut(raw, "#")
	if !hasField || strings.Contains(rawField, "#") {
		return result, errors.New("field selector is required")
	}
	field, err := url.PathUnescape(rawField)
	if err != nil || !fieldPattern.MatchString(field) || strings.Contains(field, "#") {
		return result, errors.New("invalid field selector")
	}
	pathPart, rawQuery, hasQuery := strings.Cut(base, "?")
	if strings.Contains(rawQuery, "?") {
		return result, errors.New("invalid query")
	}
	segments := strings.Split(pathPart, "/")
	if len(segments) < 2 {
		return result, errors.New("mount and path are required")
	}
	for _, segment := range segments {
		if !pathSegmentPattern.MatchString(segment) {
			return result, errors.New("invalid mount or path")
		}
	}

	if hasQuery {
		values, err := url.ParseQuery(rawQuery)
		if err != nil || len(values) != 1 || len(values["version"]) != 1 {
			return result, errors.New("invalid version query")
		}
		result.version, err = strconv.ParseUint(values.Get("version"), 10, 64)
		if err != nil || result.version == 0 {
			return result, errors.New("invalid version")
		}
	}
	result.mount = segments[0]
	result.path = strings.Join(segments[1:], "/")
	result.field = field
	result.canonical = canonicalReference(result)
	return result, nil
}

func canonicalReference(ref Reference) string {
	var builder strings.Builder
	builder.WriteString(ref.mount)
	builder.WriteByte('/')
	builder.WriteString(ref.path)
	if ref.version > 0 {
		builder.WriteString("?version=")
		builder.WriteString(strconv.FormatUint(ref.version, 10))
	}
	builder.WriteByte('#')
	builder.WriteString(url.PathEscape(ref.field))
	return builder.String()
}

func (p *Provider) Fetch(ctx context.Context, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := ctx.Err(); err != nil {
		return secretprovider.Result{}, err
	}
	ref, ok := reference.(Reference)
	if !ok || ref.ProviderKind() != p.Kind() || ref.mount == "" || ref.path == "" || ref.field == "" {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	token, err := p.tokens.Token(ctx)
	if err != nil || len(token) == 0 {
		vaultcrypto.WipeBytes(token)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return secretprovider.Result{}, ctxErr
		}
		if errors.Is(err, openbaoauth.ErrDenied) {
			return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeAccessDenied)
		}
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	defer vaultcrypto.WipeBytes(token)

	endpoint := p.address + "/v1/" + ref.mount + "/data/" + ref.path
	if ref.version > 0 {
		endpoint += "?version=" + strconv.FormatUint(ref.version, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	req.Header.Set("X-Vault-Token", string(token))
	resp, err := p.client.Do(req)
	req.Header.Del("X-Vault-Token")
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return secretprovider.Result{}, ctxErr
		}
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return secretprovider.Result{}, statusError(resp.StatusCode)
	}

	var response struct {
		Data struct {
			Data     map[string]json.RawMessage `json:"data"`
			Metadata struct {
				DeletionTime string `json:"deletion_time"`
				Destroyed    bool   `json:"destroyed"`
				Version      uint64 `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, secretprovider.MaxSecretBytes+1)).Decode(&response); err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	defer func() {
		for _, raw := range response.Data.Data {
			vaultcrypto.WipeBytes(raw)
		}
	}()
	metadata := response.Data.Metadata
	if metadata.Version == 0 || (ref.version > 0 && metadata.Version != ref.version) {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	if metadata.Destroyed || metadata.DeletionTime != "" {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeNotFound)
	}
	raw, ok := response.Data.Data[ref.field]
	if !ok {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeNotFound)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	valueBytes := []byte(value)
	defer vaultcrypto.WipeBytes(valueBytes)
	return secretprovider.NewResult(valueBytes, strconv.FormatUint(metadata.Version, 10))
}

func validateAddress(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("OpenBao address must be an HTTPS origin without credentials")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return secretprovider.NewError(secretprovider.CodeAccessDenied)
	case http.StatusNotFound:
		return secretprovider.NewError(secretprovider.CodeNotFound)
	case http.StatusBadRequest:
		return secretprovider.NewError(secretprovider.CodeInvalidReference)
	default:
		return secretprovider.NewError(secretprovider.CodeUnavailable)
	}
}
