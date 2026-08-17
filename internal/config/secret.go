package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const DefaultMaxSecretBytes int64 = 64 << 10

var (
	// ErrSecretReferenceRequired is deliberately value-free so a TOML decoder
	// cannot echo an accidentally inlined secret through the returned error.
	ErrSecretReferenceRequired = errors.New("sensitive configuration values must use env:// or file:// references")
	envNamePattern             = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// SecretRef is a non-secret locator for a value in the process environment or
// a mounted file. Its fields are private so callers cannot construct an
// unvalidated reference accidentally.
type SecretRef struct {
	scheme string
	target string
}

func ParseSecretRef(raw string) (SecretRef, error) {
	switch {
	case strings.HasPrefix(raw, "env://"):
		name := strings.TrimPrefix(raw, "env://")
		if !envNamePattern.MatchString(name) {
			return SecretRef{}, fmt.Errorf("invalid env secret reference")
		}
		return SecretRef{scheme: "env", target: name}, nil
	case strings.HasPrefix(raw, "file://"):
		path := strings.TrimPrefix(raw, "file://")
		if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return SecretRef{}, fmt.Errorf("invalid file secret reference")
		}
		for _, element := range strings.Split(filepath.ToSlash(path), "/") {
			if element == ".." {
				return SecretRef{}, fmt.Errorf("invalid file secret reference")
			}
		}
		return SecretRef{scheme: "file", target: filepath.Clean(path)}, nil
	default:
		return SecretRef{}, ErrSecretReferenceRequired
	}
}

func (r *SecretRef) UnmarshalText(text []byte) error {
	parsed, err := ParseSecretRef(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

func (r SecretRef) IsZero() bool { return r.scheme == "" }

func (r SecretRef) String() string {
	if r.IsZero() {
		return ""
	}
	return r.scheme + "://" + r.target
}

// SecretValue contains resolved bytes but formats and serializes only its
// non-secret reference. It intentionally does not expose the backing slice.
type SecretValue struct {
	ref   SecretRef
	value []byte
	set   bool
}

func newSecretValue(ref SecretRef, value []byte) SecretValue {
	owned := append([]byte(nil), value...)
	return SecretValue{ref: ref, value: owned, set: true}
}

func (v SecretValue) IsSet() bool { return v.set }

func (v SecretValue) Ref() SecretRef { return v.ref }

func (v SecretValue) String() string {
	if !v.IsSet() {
		return ""
	}
	if !v.ref.IsZero() {
		return v.ref.String()
	}
	return "[REDACTED]"
}

func (v SecretValue) GoString() string { return v.String() }

func (v SecretValue) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

func (v SecretValue) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }

// Bytes returns a caller-owned copy. Consumers should wipe it as soon as the
// downstream API no longer needs it.
func (v SecretValue) Bytes() []byte { return append([]byte(nil), v.value...) }

// RevealString is a compatibility escape hatch for APIs such as database/sql
// that require immutable strings. Callers must keep the result narrowly scoped.
func (v SecretValue) RevealString() string { return string(v.value) }

func (v *SecretValue) Wipe() {
	if v == nil {
		return
	}
	for i := range v.value {
		v.value[i] = 0
	}
	v.value = nil
	v.set = false
}

type ReadSecretFile func(path string, maxBytes int64) ([]byte, error)

// Resolver resolves typed references with a hard size bound. Tests may inject
// environment and file readers without mutating process state.
type Resolver struct {
	LookupEnv LookupEnv
	ReadFile  ReadSecretFile
	MaxBytes  int64
}

func (r Resolver) Resolve(ref SecretRef) (SecretValue, error) {
	lookup := r.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	maxBytes := r.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSecretBytes
	}
	switch ref.scheme {
	case "env":
		value, ok := lookup(ref.target)
		if !ok {
			return SecretValue{}, fmt.Errorf("secret reference %s is not set", ref.String())
		}
		if int64(len(value)) > maxBytes {
			return SecretValue{}, fmt.Errorf("secret reference %s exceeds %d bytes", ref.String(), maxBytes)
		}
		return newSecretValue(ref, []byte(value)), nil
	case "file":
		read := r.ReadFile
		if read == nil {
			read = readSecretFile
		}
		value, err := read(ref.target, maxBytes)
		if err != nil {
			return SecretValue{}, fmt.Errorf("secret reference %s: %w", ref.String(), err)
		}
		if int64(len(value)) > maxBytes {
			return SecretValue{}, fmt.Errorf("secret reference %s exceeds %d bytes", ref.String(), maxBytes)
		}
		return newSecretValue(ref, value), nil
	default:
		return SecretValue{}, fmt.Errorf("invalid secret reference")
	}
}

func readSecretFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(f, maxBytes+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > maxBytes {
		return nil, fmt.Errorf("exceeds %d bytes", maxBytes)
	}
	return buf.Bytes(), nil
}
