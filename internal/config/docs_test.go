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
				return []byte("postgres://agentvault:example@postgres.example/agentvault?sslmode=require"), nil
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
		}
	}
	if documents != 1 {
		t.Fatalf("deployment documents = %d, want 1", documents)
	}
	kustomization, err := os.ReadFile(filepath.Join(root, "examples", "kubernetes", "fleet", "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kustomization), "server.toml") {
		t.Fatal("kustomization does not generate ConfigMap from validated server.toml")
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
