package openbao

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/keywrap"
)

type rotatingTokenSource struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (s *rotatingTokenSource) Token(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return []byte("ephemeral-token-" + string(rune('0'+s.calls))), nil
}

func TestOpenBaoTransitWrapUnwrapAndContext(t *testing.T) {
	var encryptedContext string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.Header.Get("X-Vault-Token"), "ephemeral-token-") {
			http.Error(w, "denied SECRET-DETAIL", http.StatusForbidden)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		switch req.URL.Path {
		case "/v1/transit/encrypt/agent-vault":
			encryptedContext = body["associated_data"]
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v7:opaque-ciphertext"}}`))
		case "/v1/transit/decrypt/agent-vault":
			if body["associated_data"] != encryptedContext {
				http.Error(w, "context mismatch SECRET-DETAIL", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"plaintext":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)) + `"}}`))
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	tokens := &rotatingTokenSource{}
	wrapper, err := New(Options{Address: server.URL, KeyName: "agent-vault", TokenSource: tokens, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	binding := keywrap.Binding{InstanceID: "instance-1"}
	wrapped, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{4}, 32), binding)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.KeyVersion != "7" || string(wrapped.Ciphertext) != "vault:v7:opaque-ciphertext" {
		t.Fatalf("wrapped = %#v", wrapped)
	}
	plaintext, err := wrapper.Unwrap(context.Background(), wrapped, binding)
	if err != nil || !bytes.Equal(plaintext, bytes.Repeat([]byte{4}, 32)) {
		t.Fatalf("unwrap = %x, %v", plaintext, err)
	}
	if tokens.calls != 2 {
		t.Fatalf("ephemeral authentication calls = %d, want 2", tokens.calls)
	}
	if wrapper.Identity().Provider != "openbao-transit" || !strings.Contains(wrapper.Identity().KeyID, "transit/keys/agent-vault") {
		t.Fatalf("identity = %#v", wrapper.Identity())
	}
	if _, err := wrapper.Unwrap(context.Background(), wrapped, keywrap.Binding{InstanceID: "wrong"}); err == nil || strings.Contains(err.Error(), "SECRET-DETAIL") {
		t.Fatalf("context mismatch leaked or succeeded: %v", err)
	}
}

func TestOpenBaoFailsClosedOnAuthAndMalformedResponses(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"ciphertext":"not-transit"}}`))
	}))
	defer server.Close()
	tokens := &rotatingTokenSource{}
	wrapper, err := New(Options{Address: server.URL, KeyName: "key", TokenSource: tokens, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{1}, 32), keywrap.Binding{InstanceID: "instance"}); err == nil {
		t.Fatal("malformed Transit response was accepted")
	}
	tokens.err = errors.New("revoked access with SECRET-TOKEN")
	if _, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{1}, 32), keywrap.Binding{InstanceID: "instance"}); err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("revoked auth leaked or succeeded: %v", err)
	}
}

func TestOpenBaoConfigurationValidation(t *testing.T) {
	tokens := &rotatingTokenSource{}
	for _, opts := range []Options{
		{Address: "http://bao.example", KeyName: "key", TokenSource: tokens},
		{Address: "https://user:pass@bao.example", KeyName: "key", TokenSource: tokens},
		{Address: "https://bao.example", Mount: "../transit", KeyName: "key", TokenSource: tokens},
		{Address: "https://bao.example", KeyName: "", TokenSource: tokens},
		{Address: "https://bao.example", KeyName: "key"},
	} {
		if _, err := New(opts); err == nil {
			t.Fatalf("invalid OpenBao config accepted: %#v", opts)
		}
	}
}
