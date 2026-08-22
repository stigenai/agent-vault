package fleetplan

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/secretprovider"
)

type exampleProviderCatalog struct{}

type exampleReference struct {
	kind string
	raw  string
}

func (exampleProviderCatalog) Parse(name, raw string) (secretprovider.Reference, error) {
	kind := map[string]string{
		"aws-production":         secretprovider.KindAWSSecretsManager,
		"bao-production":         secretprovider.KindOpenBaoKV2,
		"onepassword-production": secretprovider.KindOnePassword,
	}[name]
	if kind == "" {
		return nil, secretprovider.NewError(secretprovider.CodeProviderNotFound)
	}
	return exampleReference{kind: kind, raw: raw}, nil
}

func (r exampleReference) ProviderKind() string { return r.kind }
func (r exampleReference) Canonical() string    { return r.raw }

func TestDocumentedImportPlanRedactsLocalSelectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	manifest, err := fleetconfig.LoadFiles([]string{
		filepath.Join(root, "examples", "kubernetes", "fleet", "desired-state", "imports.toml"),
	}, fleetconfig.LoadOptions{Providers: exampleProviderCatalog{}, ImportProviders: exampleProviderCatalog{}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Build(manifest, fleetstate.State{SchemaVersion: fleetstate.SchemaVersion}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"env://", "file://", "stdin://", "/var/run/secrets/bootstrap"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("documented plan leaked local selector %q: %s", forbidden, encoded)
		}
	}
	if plan.Blocked || plan.Summary.Create != 7 {
		t.Fatalf("documented import plan = %#v", plan)
	}
	if digest, err := Digest(plan); err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("documented plan digest = %q error=%v", digest, err)
	}
}

var _ fleetconfig.ProviderReferences = exampleProviderCatalog{}
var _ secretprovider.Reference = exampleReference{}
