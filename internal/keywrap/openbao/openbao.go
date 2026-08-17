package openbao

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
)

var pathSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var transitCiphertext = regexp.MustCompile(`^vault:v([1-9][0-9]*):`)

type TokenSource interface {
	Token(context.Context) ([]byte, error)
}

type Options struct {
	Address     string
	Mount       string
	KeyName     string
	TokenSource TokenSource
	HTTPClient  *http.Client
}

type Wrapper struct {
	address    string
	mount      string
	keyName    string
	keyID      string
	tokens     TokenSource
	httpClient *http.Client
}

func New(opts Options) (*Wrapper, error) {
	address, err := validateAddress(opts.Address)
	if err != nil {
		return nil, err
	}
	mount := strings.TrimSpace(opts.Mount)
	if mount == "" {
		mount = "transit"
	}
	if !pathSegment.MatchString(mount) || !pathSegment.MatchString(opts.KeyName) {
		return nil, errors.New("OpenBao Transit mount or key name is invalid")
	}
	if opts.TokenSource == nil {
		return nil, errors.New("OpenBao authentication source is required")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	return &Wrapper{
		address: address, mount: mount, keyName: opts.KeyName,
		keyID:  strings.TrimPrefix(address, "https://") + "/" + mount + "/keys/" + opts.KeyName,
		tokens: opts.TokenSource, httpClient: client,
	}, nil
}

func (w *Wrapper) Identity() keywrap.Identity {
	return keywrap.Identity{Provider: "openbao-transit", KeyID: w.keyID}
}

func (w *Wrapper) Wrap(ctx context.Context, plaintext []byte, binding keywrap.Binding) (keywrap.WrappedDEK, error) {
	if err := keywrap.ValidateBinding(binding); err != nil {
		return keywrap.WrappedDEK{}, err
	}
	var response struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := w.call(ctx, "encrypt", map[string]string{
		"plaintext":       base64.StdEncoding.EncodeToString(plaintext),
		"associated_data": base64.StdEncoding.EncodeToString([]byte(binding.InstanceID)),
	}, &response); err != nil {
		return keywrap.WrappedDEK{}, err
	}
	version, err := ciphertextVersion(response.Data.Ciphertext)
	if err != nil {
		return keywrap.WrappedDEK{}, errors.New("OpenBao Transit returned malformed ciphertext")
	}
	return keywrap.WrappedDEK{Ciphertext: []byte(response.Data.Ciphertext), KeyVersion: version}, nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped keywrap.WrappedDEK, binding keywrap.Binding) ([]byte, error) {
	if err := keywrap.ValidateBinding(binding); err != nil {
		return nil, err
	}
	version, err := ciphertextVersion(string(wrapped.Ciphertext))
	if err != nil || (wrapped.KeyVersion != "" && wrapped.KeyVersion != version) {
		return nil, errors.New("OpenBao Transit ciphertext metadata is invalid")
	}
	var response struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := w.call(ctx, "decrypt", map[string]string{
		"ciphertext":      string(wrapped.Ciphertext),
		"associated_data": base64.StdEncoding.EncodeToString([]byte(binding.InstanceID)),
	}, &response); err != nil {
		return nil, err
	}
	plaintext, err := base64.StdEncoding.Strict().DecodeString(response.Data.Plaintext)
	if err != nil || len(plaintext) != 32 {
		vaultcrypto.WipeBytes(plaintext)
		return nil, errors.New("OpenBao Transit returned malformed plaintext")
	}
	return plaintext, nil
}

func (w *Wrapper) call(ctx context.Context, operation string, requestBody any, responseBody any) error {
	token, err := w.tokens.Token(ctx)
	if err != nil || len(token) == 0 {
		vaultcrypto.WipeBytes(token)
		return errors.New("OpenBao authentication failed")
	}
	defer vaultcrypto.WipeBytes(token)
	body, err := json.Marshal(requestBody)
	if err != nil {
		return errors.New("encode OpenBao Transit request failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		w.address+"/v1/"+w.mount+"/"+operation+"/"+w.keyName, bytes.NewReader(body))
	if err != nil {
		return errors.New("create OpenBao Transit request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", string(token))
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return errors.New("OpenBao Transit request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("OpenBao Transit %s denied", operation)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(responseBody); err != nil {
		return errors.New("OpenBao Transit returned malformed response")
	}
	return nil
}

func validateAddress(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("OpenBao address must be an HTTPS origin without credentials")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func ciphertextVersion(ciphertext string) (string, error) {
	match := transitCiphertext.FindStringSubmatch(ciphertext)
	if len(match) != 2 || len(ciphertext) > 1<<20 {
		return "", errors.New("malformed Transit ciphertext")
	}
	version, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(version, 10), nil
}
