// Package openbaoauth obtains short-lived OpenBao tokens from rotating SPIFFE
// workload identities. Tokens are returned as owned bytes and are never
// cached or persisted by this package.
package openbaoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
)

type TokenSource interface {
	// Token returns caller-owned bytes. The caller must wipe them immediately
	// after the OpenBao request completes.
	Token(context.Context) ([]byte, error)
}

var (
	ErrDenied      = errors.New("OpenBao workload authentication denied")
	ErrUnavailable = errors.New("OpenBao workload authentication unavailable")
	pathSegment    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type loginRequest struct {
	Name string `json:"name,omitempty"`
	Role string `json:"role,omitempty"`
	JWT  string `json:"jwt,omitempty"`
}

func login(ctx context.Context, client *http.Client, loginURL string, request loginRequest) ([]byte, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer vaultcrypto.WipeBytes(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, ErrDenied
		}
		return nil, ErrUnavailable
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil || result.Auth.ClientToken == "" {
		return nil, ErrUnavailable
	}
	token := []byte(result.Auth.ClientToken)
	result.Auth.ClientToken = ""
	return token, nil
}

func validateAddress(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("OpenBao address must be an HTTPS origin without credentials")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validateAuthMountRole(mount, role, defaultMount string) (string, string, error) {
	mount = strings.TrimSpace(mount)
	if mount == "" {
		mount = defaultMount
	}
	role = strings.TrimSpace(role)
	if !pathSegment.MatchString(mount) || !pathSegment.MatchString(role) {
		return "", "", errors.New("OpenBao authentication mount or role is invalid")
	}
	return mount, role, nil
}
