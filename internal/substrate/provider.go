// Package substrate makes Agent Vault a Substrate egress credential provider:
// a gRPC CredentialProvider.FetchSecret server the Substrate egress gateway
// dials over mTLS to fill an actor's request header from a vault credential.
// The secret goes to the gateway only; the actor never sees it.
//
// URIs are ate-secret://agent-vault/<vault>/<credential-key>. The caller must
// be the gateway (pinned URI SAN); the actor named in the request must be an
// active Agent Vault agent whose SPIFFE ID equals actor_spiffe_id and that
// holds a grant (any role) on <vault>.
package substrate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/substrate/credproviderpb"
)

const (
	// ProviderName is the ate-secret:// URI host this provider serves.
	ProviderName = "agent-vault"
	// DefaultGatewayIdentity is the Substrate egress gateway's pod identity.
	DefaultGatewayIdentity = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	// DefaultActorTrustDomain is the trust domain Substrate mints actor IDs in.
	DefaultActorTrustDomain = "substrate-actor.local"
)

// Store is the narrow persistence surface FetchSecret needs.
type Store interface {
	GetAgentBySPIFFEID(ctx context.Context, spiffeID string) (*store.Agent, error)
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
}

// SecretRef is a parsed ate-secret://agent-vault/<vault>/<key> URI.
type SecretRef struct {
	Vault string
	Key   string
}

// ParseURI parses and strictly validates an agent-vault credential URI.
func ParseURI(raw string) (SecretRef, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return SecretRef{}, fmt.Errorf("parsing credential URI: %w", err)
	}
	if u.Scheme != "ate-secret" || u.Host != ProviderName || u.User != nil {
		return SecretRef{}, fmt.Errorf("credential URI must be ate-secret://%s/<vault>/<key>", ProviderName)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.EscapedPath() != u.Path {
		return SecretRef{}, fmt.Errorf("credential URI must not carry a query, fragment, or percent-encoding")
	}
	seg := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(seg) != 2 || seg[0] == "" || seg[1] == "" {
		return SecretRef{}, fmt.Errorf("credential URI must be ate-secret://%s/<vault>/<key>", ProviderName)
	}
	return SecretRef{Vault: seg[0], Key: seg[1]}, nil
}

// Provider implements credproviderpb.CredentialProviderServer over the vault store.
type Provider struct {
	credproviderpb.UnimplementedCredentialProviderServer
	store            Store
	encKey           []byte
	actorTrustDomain string
}

// NewProvider builds a provider. encKey is the vault DEK (shared, not copied,
// so the server's shutdown wipe covers it).
func NewProvider(s Store, encKey []byte, actorTrustDomain string) *Provider {
	return &Provider{store: s, encKey: encKey, actorTrustDomain: actorTrustDomain}
}

var errDenied = status.Error(codes.PermissionDenied, "actor is not permitted to resolve this credential")

// FetchSecret authorizes the actor against the vault, then returns the
// decrypted credential. Status codes follow the Substrate contract:
// PermissionDenied/NotFound → 403, Unavailable → retryable 503.
func (p *Provider) FetchSecret(ctx context.Context, req *credproviderpb.FetchSecretRequest) (*credproviderpb.FetchSecretResponse, error) {
	ref, err := ParseURI(req.GetUri())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	actor := req.GetActorSpiffeId()
	if u, err := url.Parse(actor); err != nil || u.Scheme != "spiffe" || u.Host != p.actorTrustDomain {
		slog.WarnContext(ctx, "substrate credential denied: actor outside trust domain", "vault", ref.Vault)
		return nil, errDenied
	}

	agent, err := p.store.GetAgentBySPIFFEID(ctx, actor)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.WarnContext(ctx, "substrate credential denied: actor not registered", "actor", actor, "vault", ref.Vault)
			return nil, errDenied
		}
		return nil, status.Error(codes.Unavailable, "agent lookup failed")
	}
	if agent.Status != "active" || agent.RevokedAt != nil || agent.SPIFFEID != actor {
		slog.WarnContext(ctx, "substrate credential denied: agent inactive", "actor", actor, "vault", ref.Vault)
		return nil, errDenied
	}

	// A missing vault and a missing grant both deny, so an actor cannot probe
	// which vaults exist.
	vault, err := p.store.GetVault(ctx, ref.Vault)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.Unavailable, "vault lookup failed")
	}
	if vault == nil {
		slog.WarnContext(ctx, "substrate credential denied: no grant", "actor", actor, "vault", ref.Vault)
		return nil, errDenied
	}
	role, err := p.store.GetVaultRole(ctx, agent.ID, vault.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.Unavailable, "grant lookup failed")
	}
	if role == "" {
		slog.WarnContext(ctx, "substrate credential denied: no grant", "actor", actor, "vault", ref.Vault)
		return nil, errDenied
	}

	// ponytail: static (and already-connected OAuth) credentials only; no
	// refresh or dynamic leases here — reuse brokercore's resolver if needed.
	cred, err := p.store.GetCredential(ctx, vault.ID, ref.Key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Errorf(codes.NotFound, "credential %q not found in vault %q", ref.Key, ref.Vault)
		}
		return nil, status.Error(codes.Unavailable, "credential lookup failed")
	}
	plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, p.encKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "credential could not be decrypted")
	}
	if len(plaintext) == 0 {
		return nil, status.Errorf(codes.NotFound, "credential %q in vault %q has no value", ref.Key, ref.Vault)
	}
	slog.InfoContext(ctx, "substrate credential resolved", "actor", actor, "agent", agent.Name, "vault", ref.Vault, "key", ref.Key)
	return &credproviderpb.FetchSecretResponse{OpaqueBytes: plaintext}, nil
}

// TLSFiles names the projected files the provider serves mTLS with.
type TLSFiles struct {
	// ServerCredBundle is a PEM private key + certificate chain (the
	// servicedns.podcert.ate.dev podCertificate projection).
	ServerCredBundle string
	// ClientCAFile is the CA bundle the gateway's client cert must chain to
	// (the podidentity.podcert.ate.dev ClusterTrustBundle projection).
	ClientCAFile string
	// GatewayIdentity is the only client URI SAN admitted.
	GatewayIdentity string
}

// ServerTLSConfig requires a client cert that chains to ClientCAFile and
// carries GatewayIdentity as a URI SAN. Both files are re-read per handshake
// so podCertificate rotation needs no restart.
func ServerTLSConfig(f TLSFiles) (*tls.Config, error) {
	if f.ServerCredBundle == "" || f.ClientCAFile == "" || f.GatewayIdentity == "" {
		return nil, fmt.Errorf("server cred bundle, client CA file, and gateway identity are required")
	}
	if _, err := loadPool(f.ClientCAFile); err != nil {
		return nil, err
	}
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		b, err := os.ReadFile(f.ServerCredBundle)
		if err != nil {
			return nil, err
		}
		c, err := tls.X509KeyPair(b, b)
		return &c, err
	}
	verifySAN := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("client certificate required")
		}
		for _, u := range cs.PeerCertificates[0].URIs {
			if u.String() == f.GatewayIdentity {
				return nil
			}
		}
		return fmt.Errorf("client identity %v is not the gateway %q", cs.PeerCertificates[0].URIs, f.GatewayIdentity)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := loadPool(f.ClientCAFile)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:       tls.VersionTLS13,
				GetCertificate:   getCert,
				ClientAuth:       tls.RequireAndVerifyClientCert,
				ClientCAs:        pool,
				VerifyConnection: verifySAN,
			}, nil
		},
	}, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading client CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("client CA file %s has no certificates", path)
	}
	return pool, nil
}

// NewGRPCServer returns a gRPC server serving p over tlsCfg.
func NewGRPCServer(p *Provider, tlsCfg *tls.Config) *grpc.Server {
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	credproviderpb.RegisterCredentialProviderServer(gs, p)
	return gs
}
