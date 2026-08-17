package fleetconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type rawManifest struct {
	SchemaVersion int        `toml:"schema_version"`
	Manager       string     `toml:"manager"`
	Agents        []rawAgent `toml:"agents"`
	Vaults        []rawVault `toml:"vaults"`
}

type rawAgent struct {
	Name     string `toml:"name"`
	SPIFFEID string `toml:"spiffe_id"`
	Role     string `toml:"role"`
}

type rawVault struct {
	Name        string          `toml:"name"`
	Agents      []rawVaultAgent `toml:"agents"`
	Grants      []Grant         `toml:"grants"`
	Services    []rawService    `toml:"services"`
	Credentials []rawCredential `toml:"credentials"`
	Imports     []rawImport     `toml:"imports"`
}

type rawVaultAgent struct {
	Name         string `toml:"name"`
	SPIFFEID     string `toml:"spiffe_id"`
	InstanceRole string `toml:"instance_role"`
	Role         string `toml:"role"`
}

type rawService struct {
	Name          string            `toml:"name"`
	Host          string            `toml:"host"`
	Path          string            `toml:"path"`
	Port          *int              `toml:"port"`
	Enabled       *bool             `toml:"enabled"`
	Auth          rawAuth           `toml:"auth"`
	Substitutions []rawSubstitution `toml:"substitutions"`
}

type rawAuth struct {
	Kind       string            `toml:"kind"`
	Credential string            `toml:"credential"`
	Username   string            `toml:"username"`
	Password   string            `toml:"password"`
	Header     string            `toml:"header"`
	Prefix     string            `toml:"prefix"`
	Headers    map[string]string `toml:"headers"`
}

type rawSubstitution struct {
	Credential  string   `toml:"credential"`
	Placeholder string   `toml:"placeholder"`
	In          []string `toml:"in"`
}

type rawCredential struct {
	Name            string `toml:"name"`
	Mode            string `toml:"mode"`
	Source          string `toml:"source"`
	Reference       string `toml:"ref"`
	RefreshInterval string `toml:"refresh_interval"`
	MaxStaleness    string `toml:"max_staleness"`
}

type rawImport struct {
	Name      string `toml:"name"`
	From      string `toml:"from"`
	Source    string `toml:"source"`
	Reference string `toml:"ref"`
}

// LoadFiles strictly decodes, validates, and deterministically merges files.
// It completes all validation before returning any desired state to callers.
func LoadFiles(paths []string, options LoadOptions) (*Manifest, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one fleet manifest is required")
	}
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	for i := 1; i < len(ordered); i++ {
		if ordered[i] == ordered[i-1] {
			return nil, fmt.Errorf("fleet manifest path supplied more than once: %s", ordered[i])
		}
	}

	raw := make([]rawManifest, 0, len(ordered))
	for _, path := range ordered {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fleet manifest %s: %w", path, err)
		}
		var document rawManifest
		decoder := toml.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			return nil, sanitizedDecodeError(path, err)
		}
		raw = append(raw, document)
	}

	return normalizeAndValidate(raw, options)
}

func sanitizedDecodeError(path string, err error) error {
	var missing *toml.StrictMissingError
	if errors.As(err, &missing) && len(missing.Errors) > 0 {
		first := missing.Errors[0]
		line, column := first.Position()
		key := strings.Join(first.Key(), ".")
		if len(missing.Errors) == 1 {
			return fmt.Errorf("fleet manifest %s: unknown key %q at line %d, column %d", path, key, line, column)
		}
		return fmt.Errorf("fleet manifest %s: unknown key %q at line %d, column %d (%d unknown keys)", path, key, line, column, len(missing.Errors))
	}
	var decode *toml.DecodeError
	if errors.As(err, &decode) {
		line, column := decode.Position()
		return fmt.Errorf("fleet manifest %s: invalid TOML at line %d, column %d", path, line, column)
	}
	return fmt.Errorf("fleet manifest %s: invalid TOML schema", path)
}
