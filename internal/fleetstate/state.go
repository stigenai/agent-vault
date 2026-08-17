// Package fleetstate defines the redacted current-state wire contract shared
// by the server, CLI planner, and apply precondition checks.
package fleetstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Infisical/agent-vault/internal/broker"
)

const SchemaVersion = 1

type State struct {
	SchemaVersion int        `json:"schema_version"`
	Resources     []Resource `json:"resources"`
}

type Resource struct {
	Kind     string          `json:"kind"`
	Vault    string          `json:"vault,omitempty"`
	Name     string          `json:"name"`
	Manager  string          `json:"manager,omitempty"`
	Revision int64           `json:"revision"`
	ETag     string          `json:"etag"`
	Spec     json.RawMessage `json:"spec"`
}

type VaultSpec struct {
	Name string `json:"name"`
}

type AgentSpec struct {
	Name     string `json:"name"`
	SPIFFEID string `json:"spiffe_id"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type GrantSpec struct {
	Agent string `json:"agent"`
	Role  string `json:"role"`
}

type CredentialSpec struct {
	Name                   string `json:"name"`
	Type                   string `json:"type"`
	Mode                   string `json:"mode"`
	ProviderKind           string `json:"provider_kind,omitempty"`
	Source                 string `json:"source,omitempty"`
	Reference              string `json:"ref,omitempty"`
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds,omitempty"`
	MaxStalenessSeconds    int    `json:"max_staleness_seconds,omitempty"`
}

type ServiceSpec struct {
	Name          string                `json:"name"`
	Host          string                `json:"host"`
	Path          string                `json:"path,omitempty"`
	Port          *int                  `json:"port,omitempty"`
	Enabled       bool                  `json:"enabled"`
	Auth          ServiceAuthSpec       `json:"auth"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
}

type ServiceAuthSpec struct {
	Kind         string                `json:"kind"`
	Credential   string                `json:"credential,omitempty"`
	Username     string                `json:"username,omitempty"`
	Password     string                `json:"password,omitempty"`
	Header       string                `json:"header,omitempty"`
	PrefixSHA256 string                `json:"prefix_sha256,omitempty"`
	Headers      map[string]HeaderSpec `json:"headers,omitempty"`
}

type HeaderSpec struct {
	TemplateSHA256 string   `json:"template_sha256"`
	Credentials    []string `json:"credentials,omitempty"`
}

// NewResource canonicalizes spec into its wire representation and ETag.
func NewResource(kind, vault, name string, spec any) (Resource, error) {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return Resource{}, fmt.Errorf("encoding %s state: %w", kind, err)
	}
	return Resource{
		Kind: kind, Vault: vault, Name: name, ETag: Digest(encoded), Spec: encoded,
	}, nil
}

// RedactService converts a broker service without revealing literal custom
// header templates or API-key prefixes. Their hashes preserve comparison.
func RedactService(service broker.Service) ServiceSpec {
	auth := ServiceAuthSpec{
		Kind: service.Auth.Type, Username: service.Auth.Username, Password: service.Auth.Password,
		Header: service.Auth.Header,
	}
	switch service.Auth.Type {
	case "bearer":
		auth.Credential = service.Auth.Token
	case "api-key":
		auth.Credential = service.Auth.Key
	}
	if service.Auth.Prefix != "" {
		auth.PrefixSHA256 = Digest([]byte(service.Auth.Prefix))
	}
	if len(service.Auth.Headers) > 0 {
		auth.Headers = make(map[string]HeaderSpec, len(service.Auth.Headers))
		for name, template := range service.Auth.Headers {
			keys := (&broker.Auth{Type: "custom", Headers: map[string]string{name: template}}).CredentialKeys()
			sort.Strings(keys)
			auth.Headers[name] = HeaderSpec{TemplateSHA256: Digest([]byte(template)), Credentials: keys}
		}
	}
	return ServiceSpec{
		Name: service.Name, Host: service.Host, Path: service.Path, Port: service.Port,
		Enabled: service.IsEnabled(), Auth: auth, Substitutions: service.Substitutions,
	}
}

func Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
