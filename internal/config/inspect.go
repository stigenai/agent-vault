package config

// InspectedField is one effective runtime value together with the layer that
// supplied it. Sensitive values contain only their safe reference or the
// literal marker [REDACTED].
type InspectedField struct {
	Name   string      `json:"name"`
	Value  interface{} `json:"value"`
	Source Source      `json:"source"`
}

// InspectFields returns effective configuration in stable schema order.
func (r Result) InspectFields() []InspectedField {
	fields := make([]InspectedField, 0, len(fieldNames)+1)
	for _, name := range fieldNames {
		fields = append(fields, InspectedField{Name: name, Value: inspectValue(r.Config, name), Source: r.Sources[name]})
	}
	source := r.Sources["secret_providers"]
	if source == "" {
		source = SourceDefault
	}
	fields = append(fields, InspectedField{Name: "secret_providers", Value: inspectValue(r.Config, "secret_providers"), Source: source})
	return fields
}

func inspectValue(c Runtime, name string) interface{} {
	switch name {
	case "schema_version":
		return c.SchemaVersion
	case "server.host":
		return c.Server.Host
	case "server.port":
		return c.Server.Port
	case "server.proxy_port":
		return c.Server.ProxyPort
	case "server.external_address":
		return c.Server.ExternalAddress
	case "server.log_level":
		return c.Server.LogLevel
	case "server.detach":
		return c.Server.Detach
	case "database.url":
		return c.Database.URL.String()
	case "database.sqlite_path":
		return c.Database.SQLitePath
	case "database.max_open_conns":
		return c.Database.MaxOpenConns
	case "database.max_idle_conns":
		return c.Database.MaxIdleConns
	case "database.conn_max_lifetime":
		return c.Database.ConnMaxLifetime.String()
	case "database.connect_timeout":
		return c.Database.ConnectTimeout.String()
	case "database.tls_mode":
		return c.Database.TLSMode
	case "database.tls_root_cert":
		return c.Database.TLSRootCert
	case "proxy.max_request_bytes":
		return c.Proxy.MaxRequestBytes
	case "proxy.max_response_bytes":
		return c.Proxy.MaxResponseBytes
	case "proxy.allow_private_ranges":
		return c.Proxy.AllowPrivateRanges
	case "proxy.network_allowlist":
		return append([]string(nil), c.Proxy.NetworkAllowlist...)
	case "proxy.trusted_proxies":
		return append([]string(nil), c.Proxy.TrustedProxies...)
	case "auth.mode":
		return c.Auth.Mode
	case "auth.workload_api":
		return c.Auth.WorkloadAPI
	case "auth.trust_domains":
		return append([]string(nil), c.Auth.TrustDomains...)
	case "auth.bootstrap_owner_ids":
		return append([]string(nil), c.Auth.BootstrapOwnerIDs...)
	case "client.address":
		return c.Client.Address
	case "client.vault":
		return c.Client.Vault
	case "client.workload_api":
		return c.Client.WorkloadAPI
	case "client.trust_domains":
		return append([]string(nil), c.Client.TrustDomains...)
	case "encryption.legacy_master_password":
		return c.Encryption.LegacyMasterPassword.String()
	case "smtp.host":
		return c.SMTP.Host
	case "smtp.port":
		return c.SMTP.Port
	case "smtp.username":
		return c.SMTP.Username
	case "smtp.password":
		return c.SMTP.Password.String()
	case "smtp.from":
		return c.SMTP.From
	case "smtp.from_name":
		return c.SMTP.FromName
	case "smtp.tls_mode":
		return c.SMTP.TLSMode
	case "smtp.tls_skip_verify":
		return c.SMTP.TLSSkipVerify
	case "logs.max_age":
		return c.Logs.MaxAge.String()
	case "logs.max_rows_per_vault":
		return c.Logs.MaxRowsPerVault
	case "logs.retention_locked":
		return c.Logs.RetentionLocked
	case "rate_limit.profile":
		return c.RateLimit.Profile
	case "rate_limit.locked":
		return c.RateLimit.Locked
	case "telemetry.enabled":
		return c.Telemetry.Enabled
	case "secret_providers":
		providers := make([]map[string]interface{}, 0, len(c.SecretProviders))
		for _, provider := range c.SecretProviders {
			providers = append(providers, map[string]interface{}{
				"name": provider.Name, "kind": provider.Kind, "region": provider.Region,
				"address": provider.Address, "auth": provider.Auth, "auth_mount": provider.AuthMount,
				"role": provider.Role, "audience": provider.Audience,
				"trust_domains": append([]string(nil), provider.TrustDomains...), "token": provider.Token.String(),
			})
		}
		return providers
	default:
		return nil
	}
}
