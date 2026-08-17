package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkloadRelayEnvExposesOnlyProxyAndCASettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/mitm/ca.pem" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("X-MITM-Port", "14322")
		_, _ = w.Write([]byte("test-ca"))
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	env, err := workloadRelayEnv([]string{
		"PATH=/bin",
		"AGENT_VAULT_TOKEN=durable-token",
		"AGENT_VAULT_ADDR=https://vault.example",
		"SPIFFE_ENDPOINT_SOCKET=unix:///run/spire.sock",
		"AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/aws-token",
		"OP_CONNECT_TOKEN=provider-token",
		"HTTPS_PROXY=http://old-proxy:3128",
	}, server.URL, "127.0.0.1:32123", caPath)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		values[key] = value
	}
	for _, key := range []string{"AGENT_VAULT_TOKEN", "AGENT_VAULT_ADDR", "SPIFFE_ENDPOINT_SOCKET", "AWS_WEB_IDENTITY_TOKEN_FILE", "OP_CONNECT_TOKEN"} {
		if _, ok := values[key]; ok {
			t.Fatalf("sensitive child variable %s remained", key)
		}
	}
	proxyURL, err := url.Parse(values["HTTPS_PROXY"])
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL.Host != "127.0.0.1:32123" || proxyURL.User != nil {
		t.Fatalf("child proxy URL = %q", proxyURL)
	}
	if values["SSL_CERT_FILE"] != caPath {
		t.Fatalf("SSL_CERT_FILE = %q", values["SSL_CERT_FILE"])
	}
	data, err := os.ReadFile(caPath)
	if err != nil || string(data) != "test-ca" {
		t.Fatalf("CA file = %q, %v", data, err)
	}
}

func TestRunWorkloadChildPropagatesExitAndCancellation(t *testing.T) {
	err := runWorkloadChild(context.Background(), "/bin/sh", []string{"-c", "exit 23"}, []string{"PATH=/bin:/usr/bin"})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 23 {
		t.Fatalf("exit error = %#v, want code 23", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err = runWorkloadChild(ctx, "/bin/sh", []string{"-c", "trap 'exit 42' TERM; while :; do sleep 1; done"}, []string{"PATH=/bin:/usr/bin"})
	if !errors.As(err, &exitErr) || exitErr.Code != 42 {
		t.Fatalf("cancelled child error = %#v, want code 42", err)
	}
}
