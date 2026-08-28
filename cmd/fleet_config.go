package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/fleetconfig"
	"github.com/Infisical/agent-vault/internal/fleetplan"
	"github.com/Infisical/agent-vault/internal/fleetstate"
	"github.com/Infisical/agent-vault/internal/secretprovider"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
)

type fleetPlanOutput struct {
	PlanSHA256 string          `json:"plan_sha256"`
	Plan       *fleetplan.Plan `json:"plan"`
}

type fleetCommandInput struct {
	Manifest        *fleetconfig.Manifest
	Options         fleetplan.Options
	Plan            *fleetplan.Plan
	Digest          string
	Session         *session.ClientSession
	ImportProviders *fleetImportProviderSet
}

type remoteFleetReference struct {
	kind      string
	canonical string
}

func (r remoteFleetReference) ProviderKind() string { return r.kind }
func (r remoteFleetReference) Canonical() string    { return r.canonical }

type remoteFleetReferences struct {
	session *session.ClientSession
}

func (r remoteFleetReferences) Parse(source, reference string) (secretprovider.Reference, error) {
	payload, err := json.Marshal(map[string]string{"source": source, "ref": reference})
	if err != nil {
		return nil, fmt.Errorf("encode provider reference: %w", err)
	}
	var responseBody []byte
	err = withReauthRetry(r.session, r.session.Address, func(active *session.ClientSession) error {
		var requestErr error
		responseBody, requestErr = doAdminRequestWithBody(
			http.MethodPost,
			active.Address+"/v1/fleet/provider-reference/validate",
			active.Token,
			payload,
		)
		return requestErr
	})
	if err != nil {
		return nil, err
	}
	var result struct {
		Kind      string `json:"kind"`
		Canonical string `json:"canonical"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil || result.Kind == "" || result.Canonical == "" {
		return nil, errors.New("server returned an invalid provider reference response")
	}
	return remoteFleetReference{kind: result.Kind, canonical: result.Canonical}, nil
}

var fleetConfigPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Plan a fleet configuration against current server state",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		input, err := buildFleetCommandInput(cmd)
		if err != nil {
			return err
		}
		defer func() { _ = input.ImportProviders.Close() }()
		return writeFleetPlan(cmd.OutOrStdout(), input.Plan, input.Digest)
	},
}

var fleetConfigApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a reviewed fleet configuration plan",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		input, err := buildFleetCommandInput(cmd)
		if err != nil {
			return err
		}
		defer func() { _ = input.ImportProviders.Close() }()
		if input.Plan.Blocked {
			return fmt.Errorf("fleet plan %s is blocked by unmet prerequisites", input.Digest)
		}
		expected, _ := cmd.Flags().GetString("plan-sha256")
		yes, _ := cmd.Flags().GetBool("yes")
		if expected == "" {
			if !yes {
				return fmt.Errorf("review fleet plan %s, then pass --plan-sha256 %s (or --yes to approve the current plan)", input.Digest, input.Digest)
			}
			if err := writeFleetPlan(cmd.ErrOrStderr(), input.Plan, input.Digest); err != nil {
				return err
			}
			expected = input.Digest
		}
		if expected != input.Digest {
			return fmt.Errorf("reviewed plan digest %s does not match current plan %s", expected, input.Digest)
		}
		imports, err := resolveFleetImports(cmd, input.Manifest, input.Plan, input.ImportProviders)
		if err != nil {
			return err
		}
		defer wipeFleetImportPayloads(imports)

		payload, err := json.Marshal(struct {
			Manifest           *fleetconfig.Manifest        `json:"manifest"`
			Options            fleetplan.Options            `json:"options"`
			ExpectedPlanSHA256 string                       `json:"expected_plan_sha256"`
			Imports            []fleetResolvedImportPayload `json:"imports,omitempty"`
		}{input.Manifest, input.Options, expected, imports})
		if err != nil {
			return fmt.Errorf("encode fleet apply request: %w", err)
		}
		defer vaultcrypto.WipeBytes(payload)
		var responseBody []byte
		err = withReauthRetry(input.Session, input.Session.Address, func(active *session.ClientSession) error {
			var requestErr error
			responseBody, requestErr = doAdminRequestWithBody(
				http.MethodPost, active.Address+"/v1/fleet/apply", active.Token, payload,
			)
			return requestErr
		})
		if err != nil {
			return err
		}
		var response json.RawMessage
		if err := json.Unmarshal(responseBody, &response); err != nil {
			return fmt.Errorf("parse fleet apply response: %w", err)
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(response)
	},
}

func buildFleetCommandInput(cmd *cobra.Command) (*fleetCommandInput, error) {
	paths, _ := cmd.Flags().GetStringSlice("file")
	if len(paths) == 0 {
		return nil, errors.New("at least one --file is required")
	}
	sess, err := ensureSession()
	if err != nil {
		return nil, err
	}
	importProviders := &fleetImportProviderSet{}
	manifest, err := fleetconfig.LoadFiles(paths, fleetconfig.LoadOptions{
		Providers: remoteFleetReferences{session: sess}, ImportProviders: importProviders,
	})
	if err != nil {
		_ = importProviders.Close()
		return nil, err
	}
	var current fleetstate.State
	err = withReauthRetry(sess, sess.Address, func(active *session.ClientSession) error {
		body, requestErr := doAdminRequestWithBody(http.MethodGet, active.Address+"/v1/fleet/state", active.Token, nil)
		if requestErr != nil {
			return requestErr
		}
		if err := json.Unmarshal(body, &current); err != nil {
			return fmt.Errorf("parse fleet state: %w", err)
		}
		return nil
	})
	if err != nil {
		_ = importProviders.Close()
		return nil, err
	}
	options := fleetplan.Options{}
	options.Adopt, _ = cmd.Flags().GetBool("adopt")
	options.Prune, _ = cmd.Flags().GetBool("prune")
	options.PruneCredentials, _ = cmd.Flags().GetBool("prune-credentials")
	options.RefreshImports, err = fleetImportRefreshSelectors(cmd)
	if err != nil {
		_ = importProviders.Close()
		return nil, err
	}
	plan, err := fleetplan.Build(manifest, current, options)
	if err != nil {
		_ = importProviders.Close()
		return nil, err
	}
	digest, err := fleetplan.Digest(plan)
	if err != nil {
		_ = importProviders.Close()
		return nil, err
	}
	return &fleetCommandInput{
		Manifest: manifest, Options: options, Plan: plan, Digest: digest, Session: sess,
		ImportProviders: importProviders,
	}, nil
}

func writeFleetPlan(output io.Writer, plan *fleetplan.Plan, digest string) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(fleetPlanOutput{PlanSHA256: digest, Plan: plan})
}

func addFleetConfigFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceP("file", "f", nil, "fleet TOML file (repeatable; merged in lexical path order)")
	cmd.Flags().Bool("adopt", false, "adopt matching unmanaged resources")
	cmd.Flags().Bool("prune", false, "delete resources no longer in the manifest")
	cmd.Flags().Bool("prune-credentials", false, "allow credential deletion when pruning")
	cmd.Flags().StringArray("refresh-import", nil, "refresh an imported credential from its configured source (repeatable VAULT/CREDENTIAL)")
}

func fleetImportRefreshSelectors(cmd *cobra.Command) ([]fleetplan.ImportedCredentialRef, error) {
	values, _ := cmd.Flags().GetStringArray("refresh-import")
	selectors := make([]fleetplan.ImportedCredentialRef, 0, len(values))
	for _, value := range values {
		vault, name, ok := strings.Cut(value, "/")
		if !ok || vault == "" || name == "" {
			return nil, errors.New("--refresh-import must use VAULT/CREDENTIAL")
		}
		selectors = append(selectors, fleetplan.ImportedCredentialRef{Vault: vault, Name: name})
	}
	return selectors, nil
}

func init() {
	addFleetConfigFlags(fleetConfigPlanCmd)
	addFleetConfigFlags(fleetConfigApplyCmd)
	fleetConfigApplyCmd.Flags().String("plan-sha256", "", "digest of the reviewed plan")
	fleetConfigApplyCmd.Flags().BoolP("yes", "y", false, "approve and apply the current plan non-interactively")
	runtimeConfigCmd.AddCommand(fleetConfigPlanCmd, fleetConfigApplyCmd)
}

var _ fleetconfig.ProviderReferences = remoteFleetReferences{}
var _ secretprovider.Reference = remoteFleetReference{}
