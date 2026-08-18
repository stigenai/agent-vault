package config

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRuntimeConfigurationReferenceCoversSchemaAndLegacyEnvironment(t *testing.T) {
	root := repositoryRoot(t)
	docBytes, err := os.ReadFile(filepath.Join(root, "docs", "self-hosting", "runtime-configuration.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(docBytes)
	for _, field := range fieldNames {
		if !strings.Contains(doc, "`"+field+"`") {
			t.Errorf("runtime reference omits schema field %s", field)
		}
	}

	loadSource, err := os.ReadFile(filepath.Join(root, "internal", "config", "load.go"))
	if err != nil {
		t.Fatal(err)
	}
	envPattern := regexp.MustCompile(`(?:setString|setInt|setInt64|setBool|setDuration|setList|lookup)\("([A-Z][A-Z0-9_]+)"`)
	seen := make(map[string]bool)
	for _, match := range envPattern.FindAllStringSubmatch(string(loadSource), -1) {
		name := match[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !strings.Contains(doc, "`"+name+"`") {
			t.Errorf("runtime reference omits legacy environment variable %s", name)
		}
	}
}

func TestKubernetesFleetExamplesParseAndConfigValidates(t *testing.T) {
	root := repositoryRoot(t)
	configPath := filepath.Join(root, "examples", "kubernetes", "fleet", "server.toml")
	result, err := Load(Options{
		Path:      configPath,
		LookupEnv: emptyEnv,
		Resolver: Resolver{ReadFile: func(path string, _ int64) ([]byte, error) {
			switch path {
			case "/var/run/secrets/agent-vault/database-url":
				return []byte("postgres://agentvault:example@postgres.example/agentvault"), nil
			case "/var/run/secrets/agent-vault/master-password":
				return []byte("example-master-password"), nil
			default:
				return nil, os.ErrNotExist
			}
		}},
	})
	if err != nil {
		t.Fatalf("validate fleet server.toml: %v", err)
	}
	if result.Config.Server.Host != "0.0.0.0" || !result.Config.Database.URL.IsSet() {
		t.Fatalf("unexpected fleet config: %#v", result.Config)
	}

	manifest, err := os.Open(filepath.Join(root, "examples", "kubernetes", "fleet", "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer manifest.Close()
	decoder := yaml.NewDecoder(manifest)
	documents := 0
	kinds := make(map[string]bool)
	for {
		var value map[string]interface{}
		err := decoder.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parse deployment.yaml document %d: %v", documents+1, err)
		}
		if len(value) > 0 {
			documents++
			if kind, ok := value["kind"].(string); ok {
				kinds[kind] = true
			}
		}
	}
	if documents != 2 || !kinds["ServiceAccount"] || !kinds["Deployment"] {
		t.Fatalf("deployment documents = %d, kinds = %v", documents, kinds)
	}
	kustomization, err := os.ReadFile(filepath.Join(root, "examples", "kubernetes", "fleet", "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kustomization), "server.toml") {
		t.Fatal("kustomization does not generate ConfigMap from validated server.toml")
	}
}

func TestKubernetesRelayExampleUsesSeparateIsolatedPods(t *testing.T) {
	root := repositoryRoot(t)
	dir := filepath.Join(root, "examples", "kubernetes", "relay")
	cfg, err := LoadRelay(ClientOptions{Path: filepath.Join(dir, "relay.toml"), LookupEnv: emptyEnv})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRelay(cfg.Relay); err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.ListenerMode != "network" || cfg.Relay.ListenAddress != "0.0.0.0:14322" {
		t.Fatalf("relay does not explicitly opt into network listener: %#v", cfg.Relay)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest any
	if err := yaml.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse relay deployment: %v", err)
	}
	text := string(manifestBytes)
	if strings.Contains(text, "spire-agent-socket") || strings.Contains(text, "csi.spiffe.io") {
		t.Fatal("untrusted agent container mounts the SPIRE socket")
	}
	for _, required := range []string{"http://example-agent-relay:14322", "automountServiceAccountToken: false", "readOnlyRootFilesystem: true"} {
		if !strings.Contains(text, required) {
			t.Errorf("agent deployment omits %q", required)
		}
	}
	relayBytes, err := os.ReadFile(filepath.Join(dir, "relay.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	relayText := string(relayBytes)
	for _, required := range []string{"kind: Service", "name: example-agent-relay", "spire-agent-socket", "driver: csi.spiffe.io", "runAsUser: 65532", "tcpSocket:"} {
		if !strings.Contains(relayText, required) {
			t.Errorf("relay deployment omits %q", required)
		}
	}
	if strings.Contains(relayText, "NET_ADMIN") || strings.Contains(relayText, "privileged: true") {
		t.Fatal("relay example requires privileged pod permissions")
	}
	policyBytes, err := os.ReadFile(filepath.Join(dir, "network-policies.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	policyText := string(policyBytes)
	if got := strings.Count(policyText, "kind: NetworkPolicy"); got != 7 {
		t.Fatalf("network policy count = %d, want 7", got)
	}
	for _, required := range []string{"example-agent-default-deny", "example-agent-to-own-relay", "example-agent-relay-default-deny", "example-agent-relay-ingress", "example-agent-relay-to-broker", "kubernetes.io/metadata.name: agent-vault"} {
		if !strings.Contains(policyText, required) {
			t.Errorf("network policies omit %q", required)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
