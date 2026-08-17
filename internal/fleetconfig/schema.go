// Package fleetconfig loads and validates non-secret fleet desired state.
package fleetconfig

import (
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/secretprovider"
)

const SchemaVersion = 1

// ProviderReferences is the read-only subset of the provider registry needed
// to validate and canonicalize references. Parse must not fetch secret values.
type ProviderReferences interface {
	Parse(providerName, raw string) (secretprovider.Reference, error)
}

// LoadOptions supplies runtime context needed for validation.
type LoadOptions struct {
	Providers ProviderReferences
}

// Manifest is the canonical, merged desired state returned by LoadFiles.
// Nested agent declarations are normalized into Agents and Vault.Grants.
type Manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Manager       string  `json:"manager"`
	Agents        []Agent `json:"agents,omitempty"`
	Vaults        []Vault `json:"vaults,omitempty"`
}

// Agent is an instance-level workload identity. Role is an instance role and
// defaults to no-access; vault access is represented separately by Grant.
type Agent struct {
	Name     string `json:"name"`
	SPIFFEID string `json:"spiffe_id"`
	Role     string `json:"role"`
}

// Vault contains resources scoped to one vault.
type Vault struct {
	Name        string       `json:"name"`
	Grants      []Grant      `json:"grants,omitempty"`
	Services    []Service    `json:"services,omitempty"`
	Credentials []Credential `json:"credentials,omitempty"`
	Imports     []Import     `json:"imports,omitempty"`
}

// Grant gives an existing agent a role in a vault.
type Grant struct {
	Agent string `json:"agent"`
	Role  string `json:"role"`
}

// Service is a broker service rule expressed without credential values.
type Service struct {
	Name          string         `json:"name"`
	Host          string         `json:"host"`
	Path          string         `json:"path,omitempty"`
	Port          *int           `json:"port,omitempty"`
	Enabled       *bool          `json:"enabled,omitempty"`
	Auth          Auth           `json:"auth"`
	Substitutions []Substitution `json:"substitutions,omitempty"`
}

// Auth references credential identities only. Credential is used by bearer
// and api-key auth; Username and Password are used by basic auth.
type Auth struct {
	Kind       string            `json:"kind"`
	Credential string            `json:"credential,omitempty"`
	Username   string            `json:"username,omitempty"`
	Password   string            `json:"password,omitempty"`
	Header     string            `json:"header,omitempty"`
	Prefix     string            `json:"prefix,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

type Substitution struct {
	Credential  string   `json:"credential"`
	Placeholder string   `json:"placeholder"`
	In          []string `json:"in,omitempty"`
}

// Credential describes a durable provider reference. Reference is
// canonicalized during loading; no provider value is fetched.
type Credential struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	Source          string `json:"source"`
	Reference       string `json:"ref"`
	RefreshInterval string `json:"refresh_interval"`
	MaxStaleness    string `json:"max_staleness"`
	ProviderKind    string `json:"provider_kind"`
}

// Import declares a one-time CLI-side import. From is a typed local source
// (env://, file://, or stdin://). Source+Reference instead identify a
// configured provider for a one-time fetch by the CLI.
type Import struct {
	Name         string `json:"name"`
	From         string `json:"from,omitempty"`
	Source       string `json:"source,omitempty"`
	Reference    string `json:"ref,omitempty"`
	ProviderKind string `json:"provider_kind,omitempty"`
}

// BrokerService converts the validated declarative service into the broker's
// runtime representation without resolving any credential.
func (s Service) BrokerService() broker.Service {
	auth := broker.Auth{
		Type:     s.Auth.Kind,
		Username: s.Auth.Username,
		Password: s.Auth.Password,
		Header:   s.Auth.Header,
		Prefix:   s.Auth.Prefix,
		Headers:  s.Auth.Headers,
	}
	switch s.Auth.Kind {
	case "bearer":
		auth.Token = s.Auth.Credential
	case "api-key":
		auth.Key = s.Auth.Credential
	}
	subs := make([]broker.Substitution, len(s.Substitutions))
	for i, sub := range s.Substitutions {
		subs[i] = broker.Substitution{Key: sub.Credential, Placeholder: sub.Placeholder, In: sub.In}
	}
	return broker.Service{
		Name: s.Name, Host: s.Host, Path: s.Path, Port: s.Port,
		Enabled: s.Enabled, Auth: auth, Substitutions: subs,
	}
}
