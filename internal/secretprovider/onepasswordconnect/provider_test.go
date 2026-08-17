package onepasswordconnect

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/config"
	"github.com/Infisical/agent-vault/internal/secretprovider"
)

func TestNewRequiresTypedTokenReferenceAndParseCanonicalizes(t *testing.T) {
	if _, err := New(Options{Address: "https://connect.example"}); err == nil {
		t.Fatal("provider accepted missing or inline token")
	}
	provider := testProvider(t, "https://connect.example", http.DefaultClient, "env://OP_CONNECT_TOKEN", "token")
	tests := map[string]Reference{
		"vault-id/item-id/password": {
			vault: "vault-id", item: "item-id", field: "password",
			canonical: "vault-id/item-id/password",
		},
		"Production/Database/Login%20Details/api%20key": {
			vault: "Production", item: "Database", section: "Login Details", field: "api key",
			canonical: "Production/Database/Login%20Details/api%20key",
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

func TestParseReferenceRejectsAmbiguousAndUnsafeSegments(t *testing.T) {
	provider := testProvider(t, "https://connect.example", http.DefaultClient, "env://OP_CONNECT_TOKEN", "token")
	for _, raw := range []string{
		"", "vault/item", "vault/item/section/field/extra", "vault//field", "vault/item/..",
		"vault/item/%2Fetc", " vault/item/field", "vault/item/field\nvalue", "vault/item/#field",
	} {
		if _, err := provider.ParseReference(raw); secretprovider.CodeOf(err) != secretprovider.CodeInvalidReference {
			t.Fatalf("reference %q error = %v (%s)", raw, err, secretprovider.CodeOf(err))
		}
	}
}

func TestFetchSelectsSectionFieldAndTracksItemVersion(t *testing.T) {
	var mu sync.Mutex
	call := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/vaults/vault-id/items/item-id" || request.Header.Get("Authorization") != "Bearer CONNECT-TOKEN" {
			t.Errorf("request = %s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		mu.Lock()
		call++
		version := call
		mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"version":%d,"sections":[{"id":"section-id","label":"Login"}],"fields":[{"id":"username","label":"credential","value":"OTHER","section":{"id":"other"}},{"id":"password","label":"credential","value":"SECRET-%d","section":{"id":"section-id"}}]}`, version, version)
	}))
	defer server.Close()
	provider := testProvider(t, server.URL, server.Client(), "env://OP_CONNECT_TOKEN", "CONNECT-TOKEN\n")
	reference, err := provider.ParseReference("vault-id/item-id/Login/credential")
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 2; version++ {
		result, err := provider.Fetch(context.Background(), reference)
		if err != nil {
			t.Fatal(err)
		}
		if string(result.Bytes()) != fmt.Sprintf("SECRET-%d", version) || result.Version() != fmt.Sprint(version) {
			t.Fatalf("result = %q @ %q", result.Bytes(), result.Version())
		}
		owned := result.Bytes()
		result.Wipe()
		if !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("result bytes were not wiped")
		}
	}
}

func TestFetchUsesRotatedFileToken(t *testing.T) {
	var mu sync.Mutex
	token := "token-one"
	seen := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"version":1,"fields":[{"id":"password","label":"password","value":"SECRET"}]}`))
	}))
	defer server.Close()
	ref, err := config.ParseSecretRef("file:///run/secrets/op-token")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(Options{
		Address: server.URL, TokenRef: ref, HTTPClient: server.Client(),
		Resolver: config.Resolver{ReadFile: func(string, int64) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			return []byte(token), nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := provider.ParseReference("vault/item/password")
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	result.Wipe()
	mu.Lock()
	token = "token-two"
	mu.Unlock()
	result, err = provider.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	result.Wipe()
	if len(seen) != 2 || seen[0] != "Bearer token-one" || seen[1] != "Bearer token-two" {
		t.Fatalf("authorization headers = %#v", seen)
	}
}

func TestFetchSanitizesConnectAndSelectionFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		ref    string
		code   secretprovider.ErrorCode
	}{
		{name: "unavailable", status: http.StatusServiceUnavailable, body: "SECRET-UPSTREAM", ref: "vault/item/password", code: secretprovider.CodeUnavailable},
		{name: "denied", status: http.StatusUnauthorized, body: "SECRET-TOKEN", ref: "vault/item/password", code: secretprovider.CodeAccessDenied},
		{name: "missing field", body: `{"version":1,"fields":[]}`, ref: "vault/item/password", code: secretprovider.CodeNotFound},
		{name: "missing section", body: `{"version":1,"sections":[],"fields":[]}`, ref: "vault/item/Login/password", code: secretprovider.CodeNotFound},
		{name: "ambiguous field", body: `{"version":1,"fields":[{"id":"one","label":"password","value":"SECRET-1"},{"id":"two","label":"password","value":"SECRET-2"}]}`, ref: "vault/item/password", code: secretprovider.CodeInvalidResponse},
		{name: "invalid version", body: `{"version":0,"fields":[{"id":"password","value":"SECRET"}]}`, ref: "vault/item/password", code: secretprovider.CodeInvalidResponse},
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
			provider := testProvider(t, server.URL, server.Client(), "env://OP_CONNECT_TOKEN", "CONNECT-TOKEN")
			reference, err := provider.ParseReference(test.ref)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Fetch(context.Background(), reference)
			if secretprovider.CodeOf(err) != test.code {
				t.Fatalf("error = %v (%s), want %s", err, secretprovider.CodeOf(err), test.code)
			}
			for _, secret := range []string{"SECRET-UPSTREAM", "SECRET-TOKEN", "SECRET-1", "SECRET-2"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked provider detail: %v", err)
				}
			}
		})
	}
}

func testProvider(t *testing.T, address string, client *http.Client, rawRef, token string) *Provider {
	t.Helper()
	ref, err := config.ParseSecretRef(rawRef)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(Options{
		Address: address, TokenRef: ref, HTTPClient: client,
		Resolver: config.Resolver{LookupEnv: func(string) (string, bool) { return token, true }},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}
