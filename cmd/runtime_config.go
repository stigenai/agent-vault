package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	runtimeconfig "github.com/Infisical/agent-vault/internal/config"
	"github.com/spf13/cobra"
)

var runtimeConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Validate runtime configuration and reconcile fleet state",
}

var runtimeConfigValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate effective server configuration without starting it",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		defer resetServerFlagChanges(cmd)
		result, err := loadServerConfig(cmd)
		if err != nil {
			return err
		}
		if err := clearResolvedSecretEnvironment(result.Config); err != nil {
			return err
		}
		wipeRuntimeSecrets(&result.Config)
		quiet, _ := cmd.Flags().GetBool("quiet")
		if quiet {
			return nil
		}
		if result.Path == "" {
			fmt.Fprintln(cmd.OutOrStdout(), "configuration valid (defaults and environment)")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "configuration valid: %s\n", result.Path)
		}
		return nil
	},
}

var runtimeConfigInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Show redacted effective values and their configuration sources",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		defer resetServerFlagChanges(cmd)
		result, err := loadServerConfig(cmd)
		if err != nil {
			return err
		}
		if err := clearResolvedSecretEnvironment(result.Config); err != nil {
			return err
		}
		defer wipeRuntimeSecrets(&result.Config)

		format, _ := cmd.Flags().GetString("format")
		switch strings.ToLower(format) {
		case "text":
			return writeConfigInspectionText(cmd, result)
		case "json":
			return writeConfigInspectionJSON(cmd, result)
		default:
			return fmt.Errorf("invalid format %q (accepted: text, json)", format)
		}
	},
}

func writeConfigInspectionText(cmd *cobra.Command, result runtimeconfig.Result) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	if result.Path != "" {
		fmt.Fprintf(w, "CONFIG\t%s\n", result.Path)
	}
	fmt.Fprintln(w, "FIELD\tVALUE\tSOURCE")
	for _, field := range result.InspectFields() {
		encoded, err := json.Marshal(field.Value)
		if err != nil {
			return fmt.Errorf("encode %s: %w", field.Name, err)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", field.Name, encoded, field.Source)
	}
	return w.Flush()
}

func writeConfigInspectionJSON(cmd *cobra.Command, result runtimeconfig.Result) error {
	payload := struct {
		Path   string                         `json:"path,omitempty"`
		Fields []runtimeconfig.InspectedField `json:"fields"`
	}{Path: result.Path, Fields: result.InspectFields()}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("encode configuration inspection: %w", err)
	}
	return nil
}

func wipeRuntimeSecrets(cfg *runtimeconfig.Runtime) {
	if cfg == nil {
		return
	}
	cfg.Database.URL.Wipe()
	cfg.Encryption.LegacyMasterPassword.Wipe()
	cfg.SMTP.Password.Wipe()
}

func addRuntimeConfigFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("config", "", "path to versioned server TOML (also respects AGENT_VAULT_CONFIG)")
	f.String("host", DefaultHost, "override server host")
	f.Int("port", DefaultPort, "override server port")
	f.Int("mitm-port", DefaultMITMPort, "override transparent proxy port")
	f.Bool("detach", false, "override detached mode")
	f.String("log-level", "info", "override log level")
	f.Int64("max-response-bytes", 0, "override response byte limit")
	f.Int64("max-request-bytes", 1<<30, "override request byte limit")
	f.String("database-url", "", "legacy PostgreSQL URL override (prefer a TOML secret reference)")
	f.Bool("telemetry", true, "override anonymous telemetry")
}

func init() {
	addRuntimeConfigFlags(runtimeConfigValidateCmd)
	addRuntimeConfigFlags(runtimeConfigInspectCmd)
	runtimeConfigValidateCmd.Flags().BoolP("quiet", "q", false, "validate using exit status only")
	runtimeConfigInspectCmd.Flags().String("format", "text", "output format: text or json")
	runtimeConfigCmd.AddCommand(runtimeConfigValidateCmd, runtimeConfigInspectCmd)
	rootCmd.AddCommand(runtimeConfigCmd)
}
