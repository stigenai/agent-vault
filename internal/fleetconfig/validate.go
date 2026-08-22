package fleetconfig

import (
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var (
	managerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ValidateManifest validates and canonicalizes a manifest received through a
// transport other than TOML (for example, the owner-only fleet apply API).
// Provider references are parsed but secret values are never fetched.
func ValidateManifest(manifest Manifest, options LoadOptions) (*Manifest, error) {
	document := rawManifest{
		SchemaVersion: manifest.SchemaVersion,
		Manager:       manifest.Manager,
	}
	for _, agent := range manifest.Agents {
		document.Agents = append(document.Agents, rawAgent(agent))
	}
	for _, vault := range manifest.Vaults {
		rawVault := rawVault{Name: vault.Name, Grants: append([]Grant(nil), vault.Grants...)}
		for _, service := range vault.Services {
			rawService := rawService{
				Name: service.Name, Host: service.Host, Path: service.Path,
				Port: service.Port, Enabled: service.Enabled,
				Auth: rawAuth{
					Kind: service.Auth.Kind, Credential: service.Auth.Credential,
					Username: service.Auth.Username, Password: service.Auth.Password,
					Header: service.Auth.Header, Prefix: service.Auth.Prefix,
					Headers:  service.Auth.Headers,
					ClientID: service.Auth.ClientID, ClientSecret: service.Auth.ClientSecret,
					TokenURL: service.Auth.TokenURL, Scopes: append([]string(nil), service.Auth.Scopes...),
					TokenAuthMethod: service.Auth.TokenAuthMethod,
				},
			}
			for _, substitution := range service.Substitutions {
				rawService.Substitutions = append(rawService.Substitutions, rawSubstitution{
					Credential: substitution.Credential, Placeholder: substitution.Placeholder,
					In: append([]string(nil), substitution.In...),
				})
			}
			rawVault.Services = append(rawVault.Services, rawService)
		}
		for _, credential := range vault.Credentials {
			rawVault.Credentials = append(rawVault.Credentials, rawCredential{
				Name: credential.Name, Mode: credential.Mode, Source: credential.Source,
				Reference: credential.Reference, RefreshInterval: credential.RefreshInterval,
				MaxStaleness: credential.MaxStaleness,
			})
		}
		for _, item := range vault.Imports {
			rawVault.Imports = append(rawVault.Imports, rawImport{
				Name: item.Name, From: item.From, Source: item.Source, Reference: item.Reference,
			})
		}
		document.Vaults = append(document.Vaults, rawVault)
	}
	return normalizeAndValidate([]rawManifest{document}, options)
}

func normalizeAndValidate(documents []rawManifest, options LoadOptions) (*Manifest, error) {
	result := &Manifest{SchemaVersion: SchemaVersion}
	agents := map[string]Agent{}
	spiffeOwners := map[string]string{}
	vaults := map[string]*Vault{}

	for _, document := range documents {
		if document.SchemaVersion != SchemaVersion {
			return nil, fmt.Errorf("schema_version must be %d", SchemaVersion)
		}
		if !managerPattern.MatchString(document.Manager) {
			return nil, fmt.Errorf("manager must be a non-empty portable identifier of at most 128 characters")
		}
		if result.Manager == "" {
			result.Manager = document.Manager
		} else if result.Manager != document.Manager {
			return nil, fmt.Errorf("all files in one apply set must use manager %q", result.Manager)
		}

		for _, raw := range document.Agents {
			agent := Agent{Name: raw.Name, SPIFFEID: raw.SPIFFEID, Role: defaultInstanceRole(raw.Role)}
			if err := addAgent(agents, spiffeOwners, agent); err != nil {
				return nil, err
			}
		}

		for _, rawVault := range document.Vaults {
			if err := broker.ValidateSlug(rawVault.Name); err != nil {
				return nil, fmt.Errorf("vault %q: %w", rawVault.Name, err)
			}
			vault := vaults[rawVault.Name]
			if vault == nil {
				vault = &Vault{Name: rawVault.Name}
				vaults[rawVault.Name] = vault
			}

			for _, raw := range rawVault.Agents {
				agent := Agent{Name: raw.Name, SPIFFEID: raw.SPIFFEID, Role: defaultInstanceRole(raw.InstanceRole)}
				if err := addAgent(agents, spiffeOwners, agent); err != nil {
					return nil, fmt.Errorf("vault %q: %w", rawVault.Name, err)
				}
				if err := addGrant(vault, Grant{Agent: raw.Name, Role: raw.Role}); err != nil {
					return nil, err
				}
			}
			for _, grant := range rawVault.Grants {
				if err := addGrant(vault, grant); err != nil {
					return nil, err
				}
			}
			for _, raw := range rawVault.Services {
				service := serviceFromRaw(raw)
				if err := validateService(rawVault.Name, &service); err != nil {
					return nil, err
				}
				if err := addUnique(&vault.Services, service, func(v Service) string { return v.Name }, "service", rawVault.Name); err != nil {
					return nil, err
				}
			}
			for _, raw := range rawVault.Credentials {
				credential, err := validateCredential(rawVault.Name, raw, options)
				if err != nil {
					return nil, err
				}
				if err := ensureCredentialModeFree(*vault, credential.Name, false); err != nil {
					return nil, err
				}
				if err := addUnique(&vault.Credentials, credential, func(v Credential) string { return v.Name }, "credential", rawVault.Name); err != nil {
					return nil, err
				}
			}
			for _, raw := range rawVault.Imports {
				item, err := validateImport(rawVault.Name, raw, options)
				if err != nil {
					return nil, err
				}
				if err := ensureCredentialModeFree(*vault, item.Name, true); err != nil {
					return nil, err
				}
				if err := addUnique(&vault.Imports, item, func(v Import) string { return v.Name }, "import", rawVault.Name); err != nil {
					return nil, err
				}
			}
		}
	}

	for _, vault := range vaults {
		for _, grant := range vault.Grants {
			if _, ok := agents[grant.Agent]; !ok {
				return nil, fmt.Errorf("vault %q: grant references undefined agent %q", vault.Name, grant.Agent)
			}
		}
		if err := validateServiceCredentialRefs(*vault); err != nil {
			return nil, err
		}
	}

	for _, agent := range agents {
		result.Agents = append(result.Agents, agent)
	}
	for _, vault := range vaults {
		canonicalizeVault(vault)
		result.Vaults = append(result.Vaults, *vault)
	}
	sort.Slice(result.Agents, func(i, j int) bool { return result.Agents[i].Name < result.Agents[j].Name })
	sort.Slice(result.Vaults, func(i, j int) bool { return result.Vaults[i].Name < result.Vaults[j].Name })
	stdinOwner := ""
	for _, vault := range result.Vaults {
		for _, item := range vault.Imports {
			if item.From != "stdin://" {
				continue
			}
			owner := vault.Name + "/" + item.Name
			if stdinOwner != "" {
				return nil, fmt.Errorf("stdin import may be declared only once (used by %q and %q)", stdinOwner, owner)
			}
			stdinOwner = owner
		}
	}
	return result, nil
}

func defaultInstanceRole(role string) string {
	if role == "" {
		return "no-access"
	}
	return role
}

func addAgent(agents map[string]Agent, spiffeOwners map[string]string, agent Agent) error {
	if err := broker.ValidateSlug(agent.Name); err != nil {
		return fmt.Errorf("agent %q: %w", agent.Name, err)
	}
	id, err := spiffeid.FromString(agent.SPIFFEID)
	if err != nil || id.String() != agent.SPIFFEID {
		return fmt.Errorf("agent %q: spiffe_id must be an exact canonical SPIFFE ID", agent.Name)
	}
	if agent.Role != "owner" && agent.Role != "member" && agent.Role != "no-access" {
		return fmt.Errorf("agent %q: role must be owner, member, or no-access", agent.Name)
	}
	if owner, ok := spiffeOwners[agent.SPIFFEID]; ok && owner != agent.Name {
		return fmt.Errorf("SPIFFE ID is assigned to both agent %q and agent %q", owner, agent.Name)
	}
	if existing, ok := agents[agent.Name]; ok {
		if !reflect.DeepEqual(existing, agent) {
			return fmt.Errorf("agent %q has conflicting definitions", agent.Name)
		}
		return nil
	}
	agents[agent.Name] = agent
	spiffeOwners[agent.SPIFFEID] = agent.Name
	return nil
}

func addGrant(vault *Vault, grant Grant) error {
	if err := broker.ValidateSlug(grant.Agent); err != nil {
		return fmt.Errorf("vault %q grant agent %q: %w", vault.Name, grant.Agent, err)
	}
	if grant.Role != "proxy" && grant.Role != "member" && grant.Role != "admin" {
		return fmt.Errorf("vault %q grant for agent %q: role must be proxy, member, or admin", vault.Name, grant.Agent)
	}
	for _, existing := range vault.Grants {
		if existing.Agent != grant.Agent {
			continue
		}
		if !reflect.DeepEqual(existing, grant) {
			return fmt.Errorf("vault %q: agent %q has duplicate or conflicting grants", vault.Name, grant.Agent)
		}
		return nil
	}
	vault.Grants = append(vault.Grants, grant)
	return nil
}

func serviceFromRaw(raw rawService) Service {
	subs := make([]Substitution, len(raw.Substitutions))
	for i, sub := range raw.Substitutions {
		subs[i] = Substitution{Credential: sub.Credential, Placeholder: sub.Placeholder, In: append([]string(nil), sub.In...)}
		sort.Strings(subs[i].In)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Placeholder < subs[j].Placeholder })
	if len(raw.Auth.Headers) == 0 {
		raw.Auth.Headers = nil
	}
	return Service{
		Name: raw.Name, Host: raw.Host, Path: raw.Path, Port: raw.Port, Enabled: raw.Enabled,
		Auth: Auth{
			Kind: raw.Auth.Kind, Credential: raw.Auth.Credential,
			Username: raw.Auth.Username, Password: raw.Auth.Password,
			Header: raw.Auth.Header, Prefix: raw.Auth.Prefix, Headers: raw.Auth.Headers,
			ClientID: raw.Auth.ClientID, ClientSecret: raw.Auth.ClientSecret,
			TokenURL: raw.Auth.TokenURL, Scopes: append([]string(nil), raw.Auth.Scopes...),
			TokenAuthMethod: raw.Auth.TokenAuthMethod,
		},
		Substitutions: subs,
	}
}

func validateService(vaultName string, service *Service) error {
	brokerService := service.BrokerService()
	if err := broker.NormalizePort(&brokerService); err != nil {
		return fmt.Errorf("vault %q service %q: %w", vaultName, service.Name, err)
	}
	if err := broker.Validate(&broker.Config{Vault: vaultName, Services: []broker.Service{brokerService}}); err != nil {
		return fmt.Errorf("vault %q service %q: %w", vaultName, service.Name, err)
	}
	service.Host, service.Path, service.Port = brokerService.Host, brokerService.Path, brokerService.Port
	enabled := brokerService.IsEnabled()
	service.Enabled = &enabled
	for i := range service.Substitutions {
		service.Substitutions[i].In = brokerService.Substitutions[i].NormalizedIn()
		sort.Strings(service.Substitutions[i].In)
	}
	return nil
}

func validateCredential(vault string, raw rawCredential, options LoadOptions) (Credential, error) {
	result := Credential{
		Name: raw.Name, Mode: raw.Mode, Source: raw.Source, Reference: raw.Reference,
		RefreshInterval: raw.RefreshInterval, MaxStaleness: raw.MaxStaleness,
	}
	if !broker.CredentialKeyPattern.MatchString(result.Name) {
		return Credential{}, fmt.Errorf("vault %q credential name must use UPPER_SNAKE_CASE", vault)
	}
	if result.Mode != "reference" {
		return Credential{}, fmt.Errorf("vault %q credential %q: mode must be reference", vault, result.Name)
	}
	refresh, stale, err := validateDurations(result.RefreshInterval, result.MaxStaleness)
	if err != nil {
		return Credential{}, fmt.Errorf("vault %q credential %q: %w", vault, result.Name, err)
	}
	result.RefreshInterval, result.MaxStaleness = refresh, stale
	reference, err := parseProviderReference(options, result.Source, result.Reference)
	if err != nil {
		return Credential{}, fmt.Errorf("vault %q credential %q: provider reference is invalid", vault, result.Name)
	}
	result.Reference = reference.Canonical()
	result.ProviderKind = reference.ProviderKind()
	return result, nil
}

func validateDurations(refreshRaw, staleRaw string) (string, string, error) {
	refresh, err := time.ParseDuration(refreshRaw)
	if err != nil || refresh < 10*time.Second || refresh%time.Second != 0 || refresh/time.Second > math.MaxInt32 {
		return "", "", fmt.Errorf("refresh_interval must be an integral duration of at least 10s")
	}
	stale, err := time.ParseDuration(staleRaw)
	if err != nil || stale < 0 || stale%time.Second != 0 || stale/time.Second > math.MaxInt32 {
		return "", "", fmt.Errorf("max_staleness must be a non-negative integral duration")
	}
	return refresh.String(), stale.String(), nil
}

func validateImport(vault string, raw rawImport, options LoadOptions) (Import, error) {
	result := Import{Name: raw.Name, From: raw.From, Source: raw.Source, Reference: raw.Reference}
	if !broker.CredentialKeyPattern.MatchString(result.Name) {
		return Import{}, fmt.Errorf("vault %q import name must use UPPER_SNAKE_CASE", vault)
	}
	local := result.From != ""
	provider := result.Source != "" || result.Reference != ""
	if local == provider {
		return Import{}, fmt.Errorf("vault %q import %q: set exactly one of from or source+ref", vault, result.Name)
	}
	if local {
		if err := validateLocalImport(result.From); err != nil {
			return Import{}, fmt.Errorf("vault %q import %q: source is invalid or unsafe", vault, result.Name)
		}
		return result, nil
	}
	if result.Source == "" || result.Reference == "" {
		return Import{}, fmt.Errorf("vault %q import %q: source and ref must be set together", vault, result.Name)
	}
	providers := options.ImportProviders
	if providers == nil {
		providers = options.Providers
	}
	reference, err := parseProviderReferenceWith(providers, result.Source, result.Reference)
	if err != nil {
		return Import{}, fmt.Errorf("vault %q import %q: provider reference is invalid", vault, result.Name)
	}
	result.Reference = reference.Canonical()
	result.ProviderKind = reference.ProviderKind()
	return result, nil
}

func parseProviderReference(options LoadOptions, source, raw string) (secretprovider.Reference, error) {
	return parseProviderReferenceWith(options.Providers, source, raw)
}

func parseProviderReferenceWith(providers ProviderReferences, source, raw string) (secretprovider.Reference, error) {
	if providers == nil {
		return nil, fmt.Errorf("provider registry is required")
	}
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > secretprovider.MaxReferenceBytes ||
		strings.Contains(raw, "\x00") || strings.Contains(raw, "`") || strings.Contains(raw, "$(") {
		return nil, fmt.Errorf("unsafe provider reference")
	}
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"env:", "file:", "stdin:", "inline:", "literal:", "exec:", "shell:", "command:"} {
		if strings.HasPrefix(lower, prefix) {
			return nil, fmt.Errorf("unsupported provider reference")
		}
	}
	return providers.Parse(source, raw)
}

func validateLocalImport(raw string) error {
	if raw == "" || strings.Contains(raw, "\x00") || strings.Contains(raw, "`") || strings.Contains(raw, "$(") {
		return fmt.Errorf("unsafe source")
	}
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"inline:", "literal:", "exec:", "shell:", "command:"} {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("unsupported source")
		}
	}
	if raw == "stdin://" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("invalid source URI")
	}
	switch parsed.Scheme {
	case "env":
		if parsed.Host == "" || parsed.Path != "" || !envNamePattern.MatchString(parsed.Host) {
			return fmt.Errorf("invalid environment source")
		}
	case "file":
		if parsed.Host != "" || parsed.Path == "" || !filepath.IsAbs(parsed.Path) || filepath.Clean(parsed.Path) != parsed.Path {
			return fmt.Errorf("invalid file source")
		}
	default:
		return fmt.Errorf("unsupported source")
	}
	return nil
}

func ensureCredentialModeFree(vault Vault, name string, addingImport bool) error {
	if addingImport {
		for _, credential := range vault.Credentials {
			if credential.Name == name {
				return fmt.Errorf("vault %q credential %q cannot be both an import and a reference", vault.Name, name)
			}
		}
		return nil
	}
	for _, item := range vault.Imports {
		if item.Name == name {
			return fmt.Errorf("vault %q credential %q cannot be both an import and a reference", vault.Name, name)
		}
	}
	return nil
}

func validateServiceCredentialRefs(vault Vault) error {
	available := map[string]struct{}{}
	for _, credential := range vault.Credentials {
		available[credential.Name] = struct{}{}
	}
	for _, item := range vault.Imports {
		available[item.Name] = struct{}{}
	}
	for _, service := range vault.Services {
		brokerService := service.BrokerService()
		for _, key := range brokerService.CredentialKeys() {
			if _, ok := available[key]; !ok {
				return fmt.Errorf("vault %q service %q references undefined credential %q", vault.Name, service.Name, key)
			}
		}
	}
	return nil
}

func addUnique[T any](target *[]T, value T, key func(T) string, kind, vault string) error {
	for _, existing := range *target {
		if key(existing) != key(value) {
			continue
		}
		if !reflect.DeepEqual(existing, value) {
			return fmt.Errorf("vault %q %s %q has conflicting definitions", vault, kind, key(value))
		}
		return nil
	}
	*target = append(*target, value)
	return nil
}

func canonicalizeVault(vault *Vault) {
	sort.Slice(vault.Grants, func(i, j int) bool { return vault.Grants[i].Agent < vault.Grants[j].Agent })
	sort.Slice(vault.Services, func(i, j int) bool { return vault.Services[i].Name < vault.Services[j].Name })
	sort.Slice(vault.Credentials, func(i, j int) bool { return vault.Credentials[i].Name < vault.Credentials[j].Name })
	sort.Slice(vault.Imports, func(i, j int) bool { return vault.Imports[i].Name < vault.Imports[j].Name })
}
