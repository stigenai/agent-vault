// Package onepasswordconnect resolves credential fields through a 1Password
// Connect server. Connect access tokens must come from typed env:// or file://
// references and are resolved afresh for each request.
package onepasswordconnect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/config"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/secretprovider"
)

type Options struct {
	Address    string
	TokenRef   config.SecretRef
	Resolver   config.Resolver
	HTTPClient *http.Client
}

type Provider struct {
	address  string
	tokenRef config.SecretRef
	resolver config.Resolver
	client   *http.Client
}

// Reference grammar:
//
//	vault/item/field
//	vault/item/section/field
//
// Each URL-escaped segment may identify the corresponding 1Password object by
// ID or label. Field selection must resolve to exactly one field.
type Reference struct {
	vault     string
	item      string
	section   string
	field     string
	canonical string
}

func (r Reference) ProviderKind() string { return secretprovider.KindOnePassword }
func (r Reference) Canonical() string    { return r.canonical }

func New(options Options) (*Provider, error) {
	address, err := validateAddress(options.Address)
	if err != nil {
		return nil, err
	}
	if options.TokenRef.IsZero() {
		return nil, errors.New("1Password Connect token must use an env:// or file:// reference")
	}
	client := options.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport}
	}
	return &Provider{
		address: address, tokenRef: options.TokenRef, resolver: options.Resolver, client: client,
	}, nil
}

func (p *Provider) Kind() string { return secretprovider.KindOnePassword }

func (p *Provider) ParseReference(raw string) (secretprovider.Reference, error) {
	if p == nil || p.client == nil || p.tokenRef.IsZero() {
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
	parts := strings.Split(raw, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return result, errors.New("vault, item, and field are required")
	}
	decoded := make([]string, len(parts))
	for i, part := range parts {
		value, err := url.PathUnescape(part)
		if err != nil || value == "" || len(value) > 256 || strings.TrimSpace(value) != value ||
			strings.ContainsAny(value, "/?#\r\n\x00") || value == "." || value == ".." {
			return result, errors.New("invalid 1Password reference segment")
		}
		decoded[i] = value
	}
	result.vault = decoded[0]
	result.item = decoded[1]
	if len(decoded) == 3 {
		result.field = decoded[2]
	} else {
		result.section = decoded[2]
		result.field = decoded[3]
	}
	result.canonical = canonicalReference(result)
	return result, nil
}

func canonicalReference(ref Reference) string {
	parts := []string{ref.vault, ref.item}
	if ref.section != "" {
		parts = append(parts, ref.section)
	}
	parts = append(parts, ref.field)
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func (p *Provider) Fetch(ctx context.Context, reference secretprovider.Reference) (secretprovider.Result, error) {
	if err := ctx.Err(); err != nil {
		return secretprovider.Result{}, err
	}
	ref, ok := reference.(Reference)
	if !ok || ref.ProviderKind() != p.Kind() || ref.vault == "" || ref.item == "" || ref.field == "" {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidReference)
	}
	secretValue, err := p.resolver.Resolve(p.tokenRef)
	if err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	defer secretValue.Wipe()
	token := secretValue.Bytes()
	defer vaultcrypto.WipeBytes(token)
	token = bytes.TrimSpace(token)
	if len(token) == 0 {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}

	endpoint := p.address + "/v1/vaults/" + url.PathEscape(ref.vault) + "/items/" + url.PathEscape(ref.item)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeUnavailable)
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err := p.client.Do(req)
	req.Header.Del("Authorization")
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

	var item struct {
		Version  int64 `json:"version"`
		Sections []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"sections"`
		Fields []struct {
			ID      string          `json:"id"`
			Label   string          `json:"label"`
			Value   json.RawMessage `json:"value"`
			Section *struct {
				ID string `json:"id"`
			} `json:"section"`
		} `json:"fields"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, secretprovider.MaxSecretBytes+1)).Decode(&item); err != nil || item.Version <= 0 {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	defer func() {
		for i := range item.Fields {
			vaultcrypto.WipeBytes(item.Fields[i].Value)
		}
	}()
	sectionIDs := map[string]struct{}{}
	if ref.section != "" {
		for _, section := range item.Sections {
			if section.ID == ref.section || section.Label == ref.section {
				sectionIDs[section.ID] = struct{}{}
			}
		}
		if len(sectionIDs) == 0 {
			return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeNotFound)
		}
	}

	var selected json.RawMessage
	matches := 0
	for _, field := range item.Fields {
		if field.ID != ref.field && field.Label != ref.field {
			continue
		}
		if ref.section != "" {
			if field.Section == nil {
				continue
			}
			if _, ok := sectionIDs[field.Section.ID]; !ok {
				continue
			}
		}
		selected = field.Value
		matches++
	}
	if matches == 0 {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeNotFound)
	}
	if matches != 1 {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	var value string
	if err := json.Unmarshal(selected, &value); err != nil {
		return secretprovider.Result{}, secretprovider.NewError(secretprovider.CodeInvalidResponse)
	}
	valueBytes := []byte(value)
	defer vaultcrypto.WipeBytes(valueBytes)
	return secretprovider.NewResult(valueBytes, strconv.FormatInt(item.Version, 10))
}

func validateAddress(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("1Password Connect address must be an HTTPS origin without credentials")
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
