package openbaokv2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/openbaoauth"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/secretprovider/contracttest"
)

type fakeTokenSource struct {
	mu    sync.Mutex
	calls int
	token []byte
	err   error
}

func (f *fakeTokenSource) Token(context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.token, f.err
}

func TestParseReferenceCanonicalizesKVVersion(t *testing.T) {
	provider := testProvider(t, &fakeTokenSource{token: []byte("token")}, http.DefaultClient, "https://openbao.example")
	tests := map[string]Reference{
		"kv/application/prod#token": {
			mount: "kv", path: "application/prod", field: "token",
			canonical: "kv/application/prod#token",
		},
		"team-kv/application?version=12#api%20key": {
			mount: "team-kv", path: "application", field: "api key", version: 12,
			canonical: "team-kv/application?version=12#api%20key",
		},
	}
	for raw, expected := range tests {
		reference, err := provider.ParseReference(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := reference.(Reference); got != expected || got.Canonical() != expected.canonical {
			t.Fatalf("parse %q = %#v, want %#v", raw, got, expected)
		}
	}
}

func TestParseReferenceRejectsMissingFieldTraversalAndBadVersion(t *testing.T) {
	provider := testProvider(t, &fakeTokenSource{token: []byte("token")}, http.DefaultClient, "https://openbao.example")
	for _, raw := range []string{
		"", "kv/path", "kv#field", "kv/path#", "kv//path#field", "kv/../path#field",
		"kv/path?version=0#field", "kv/path?version=-1#field", "kv/path?other=1#field",
		"kv/path?version=1&version=2#field", "kv/path#field#again", "kv/path\nvalue#field",
	} {
		if _, err := provider.ParseReference(raw); secretprovider.CodeOf(err) != secretprovider.CodeInvalidReference {
			t.Fatalf("reference %q error = %v (%s)", raw, err, secretprovider.CodeOf(err))
		}
	}
}

func TestFetchReadsVersionedKVFieldAndWipesToken(t *testing.T) {
	token := []byte("EPHEMERAL-OPENBAO-TOKEN")
	tokens := &fakeTokenSource{token: token}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/kv/data/application/prod" ||
			request.URL.Query().Get("version") != "7" || request.Header.Get("X-Vault-Token") != "EPHEMERAL-OPENBAO-TOKEN" {
			t.Errorf("request = %s %s?%s token=%q", request.Method, request.URL.Path, request.URL.RawQuery, request.Header.Get("X-Vault-Token"))
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"token":"SECRET-VALUE","other":"SECRET-OTHER"},"metadata":{"deletion_time":"","destroyed":false,"version":7}}}`))
	}))
	defer server.Close()
	provider := testProvider(t, tokens, server.Client(), server.URL)
	reference, err := provider.ParseReference("kv/application/prod?version=7#token")
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Bytes()) != "SECRET-VALUE" || result.Version() != "7" {
		t.Fatalf("result = %q @ %q", result.Bytes(), result.Version())
	}
	if !bytes.Equal(token, make([]byte, len(token))) {
		t.Fatal("OpenBao token was not wiped")
	}
	owned := result.Bytes()
	result.Wipe()
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("result bytes were not wiped")
	}
}

func TestFetchRespectsDeletionAndSanitizesFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		tokens *fakeTokenSource
		code   secretprovider.ErrorCode
	}{
		{name: "soft deleted", body: `{"data":{"data":{"token":"SECRET"},"metadata":{"deletion_time":"2026-08-17T00:00:00Z","destroyed":false,"version":2}}}`, code: secretprovider.CodeNotFound},
		{name: "destroyed", body: `{"data":{"data":{},"metadata":{"deletion_time":"","destroyed":true,"version":2}}}`, code: secretprovider.CodeNotFound},
		{name: "missing field", body: `{"data":{"data":{"other":"SECRET"},"metadata":{"deletion_time":"","destroyed":false,"version":2}}}`, code: secretprovider.CodeNotFound},
		{name: "version mismatch", body: `{"data":{"data":{"token":"SECRET"},"metadata":{"deletion_time":"","destroyed":false,"version":3}}}`, code: secretprovider.CodeInvalidResponse},
		{name: "permission denied", status: http.StatusForbidden, body: "SECRET-POLICY", code: secretprovider.CodeAccessDenied},
		{name: "not found", status: http.StatusNotFound, body: "SECRET-PATH", code: secretprovider.CodeNotFound},
		{name: "auth denied", tokens: &fakeTokenSource{err: openbaoauth.ErrDenied}, code: secretprovider.CodeAccessDenied},
		{name: "auth unavailable", tokens: &fakeTokenSource{err: errors.New("SECRET-AUTH")}, code: secretprovider.CodeUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				status := test.status
				if status == 0 {
					status = http.StatusOK
				}
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			tokens := test.tokens
			if tokens == nil {
				tokens = &fakeTokenSource{token: []byte("token")}
			}
			provider := testProvider(t, tokens, server.Client(), server.URL)
			reference, err := provider.ParseReference("kv/application?version=2#token")
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Fetch(context.Background(), reference)
			if secretprovider.CodeOf(err) != test.code {
				t.Fatalf("error = %v (%s), want %s", err, secretprovider.CodeOf(err), test.code)
			}
			for _, secret := range []string{"SECRET-POLICY", "SECRET-PATH", "SECRET-AUTH"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked provider detail: %v", err)
				}
			}
		})
	}
}

func testProvider(t *testing.T, tokens openbaoauth.TokenSource, client *http.Client, address string) *Provider {
	t.Helper()
	provider, err := New(Options{Address: address, TokenSource: tokens, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestProviderCancellationContract(t *testing.T) {
	provider := testProvider(t, &fakeTokenSource{token: []byte("token")}, http.DefaultClient, "https://openbao.example")
	contracttest.RequireCancellation(t, provider, "kv/application#token")
}
