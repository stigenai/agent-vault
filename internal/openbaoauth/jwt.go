package openbaoauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

type JWTOptions struct {
	Address    string
	AuthMount  string
	Role       string
	Audience   string
	Source     jwtsvid.Source
	HTTPClient *http.Client
}

type JWTTokenSource struct {
	loginURL string
	role     string
	audience string
	source   jwtsvid.Source
	client   *http.Client
}

// NewJWTTokenSource fetches a new audience-bound JWT-SVID and performs an
// OpenBao JWT login for every Token call. Neither JWT nor OpenBao token is
// cached by the source.
func NewJWTTokenSource(options JWTOptions) (*JWTTokenSource, error) {
	address, err := validateAddress(options.Address)
	if err != nil {
		return nil, err
	}
	mount, role, err := validateAuthMountRole(options.AuthMount, options.Role, "jwt")
	if err != nil {
		return nil, err
	}
	audience := strings.TrimSpace(options.Audience)
	if options.Source == nil || audience == "" || len(audience) > 512 || strings.ContainsAny(audience, "\r\n\x00") {
		return nil, errors.New("OpenBao JWT-SVID source and audience are required")
	}
	client := options.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport}
	}
	return &JWTTokenSource{
		loginURL: address + "/v1/auth/" + mount + "/login",
		role:     role,
		audience: audience,
		source:   options.Source,
		client:   client,
	}, nil
}

func (s *JWTTokenSource) Token(ctx context.Context) ([]byte, error) {
	if s == nil || s.source == nil || s.client == nil {
		return nil, ErrUnavailable
	}
	svid, err := s.source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: s.audience})
	if err != nil || svid == nil || svid.Marshal() == "" {
		return nil, ErrUnavailable
	}
	return login(ctx, s.client, s.loginURL, loginRequest{Role: s.role, JWT: svid.Marshal()})
}
