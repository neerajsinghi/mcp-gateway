// Package auth authenticates gateway callers using static API keys or
// HS256/RS256 JWT bearer tokens.
package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

// Method identifies how a caller authenticated.
type Method string

// Supported authentication methods.
const (
	MethodAPIKey Method = "api_key"
	MethodJWT    Method = "jwt"
)

// Principal is an authenticated caller.
type Principal struct {
	// Identity is the stable caller name used for policy and audit.
	Identity string
	// Method records which mechanism authenticated the caller.
	Method Method
}

// Errors returned by Authenticate. Their messages are safe to return to
// clients; they never include token material.
var (
	ErrMissingCredentials = errors.New("missing credentials")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type apiKey struct {
	digest   [sha256.Size]byte
	identity string
}

// Authenticator verifies credentials on incoming requests.
type Authenticator struct {
	keys          []apiKey
	hsSecret      []byte
	rsKey         *rsa.PublicKey
	parser        *jwt.Parser
	identityClaim string
}

// New builds an Authenticator from configuration, resolving secrets from
// the environment and key files.
func New(c config.Auth) (*Authenticator, error) {
	a := &Authenticator{}
	for i, k := range c.APIKeys {
		var d [sha256.Size]byte
		switch {
		case k.KeyEnv != "":
			v := os.Getenv(k.KeyEnv)
			if v == "" {
				return nil, fmt.Errorf("auth.api_keys[%d]: environment variable %s is empty", i, k.KeyEnv)
			}
			d = sha256.Sum256([]byte(v))
		default:
			b, err := hex.DecodeString(k.KeySHA256)
			if err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("auth.api_keys[%d]: invalid key_sha256", i)
			}
			copy(d[:], b)
		}
		a.keys = append(a.keys, apiKey{digest: d, identity: k.Identity})
	}

	if j := c.JWT; j != nil {
		var methods []string
		if j.HS256SecretEnv != "" {
			s := os.Getenv(j.HS256SecretEnv)
			if len(s) < 32 {
				return nil, fmt.Errorf("auth.jwt: %s must hold a secret of at least 32 bytes", j.HS256SecretEnv)
			}
			a.hsSecret = []byte(s)
			methods = append(methods, jwt.SigningMethodHS256.Alg())
		}
		if j.RS256PublicKeyFile != "" {
			pem, err := os.ReadFile(j.RS256PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("auth.jwt: read public key: %w", err)
			}
			k, err := jwt.ParseRSAPublicKeyFromPEM(pem)
			if err != nil {
				return nil, fmt.Errorf("auth.jwt: parse public key: %w", err)
			}
			a.rsKey = k
			methods = append(methods, jwt.SigningMethodRS256.Alg())
		}
		opts := []jwt.ParserOption{
			jwt.WithValidMethods(methods),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(j.Leeway.Duration),
		}
		if j.Issuer != "" {
			opts = append(opts, jwt.WithIssuer(j.Issuer))
		}
		if j.Audience != "" {
			opts = append(opts, jwt.WithAudience(j.Audience))
		}
		a.parser = jwt.NewParser(opts...)
		a.identityClaim = j.IdentityClaim
		if a.identityClaim == "" {
			a.identityClaim = "sub"
		}
	}
	return a, nil
}

// Authenticate extracts and verifies credentials from r. API keys are read
// from the X-API-Key header or an Authorization bearer token; bearer tokens
// shaped like a JWT are verified as JWTs when JWT auth is configured.
func (a *Authenticator) Authenticate(r *http.Request) (Principal, error) {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return a.checkAPIKey(k)
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return Principal{}, ErrMissingCredentials
	}
	scheme, tok, ok := strings.Cut(h, " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return Principal{}, ErrInvalidCredentials
	}
	if a.parser != nil && strings.Count(tok, ".") == 2 {
		return a.checkJWT(tok)
	}
	return a.checkAPIKey(tok)
}

// checkAPIKey compares the digest of k against every configured key in
// constant time, without short-circuiting, to avoid timing side channels.
func (a *Authenticator) checkAPIKey(k string) (Principal, error) {
	d := sha256.Sum256([]byte(k))
	match := -1
	for i := range a.keys {
		if subtle.ConstantTimeCompare(d[:], a.keys[i].digest[:]) == 1 && match < 0 {
			match = i
		}
	}
	if match < 0 {
		return Principal{}, ErrInvalidCredentials
	}
	return Principal{Identity: a.keys[match].identity, Method: MethodAPIKey}, nil
}

func (a *Authenticator) checkJWT(tok string) (Principal, error) {
	claims := jwt.MapClaims{}
	_, err := a.parser.ParseWithClaims(tok, claims, a.keyFunc)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}
	id, ok := claims[a.identityClaim].(string)
	if !ok || id == "" {
		return Principal{}, ErrInvalidCredentials
	}
	return Principal{Identity: id, Method: MethodJWT}, nil
}

// keyFunc selects the verification key from the token's algorithm. It
// checks the concrete signing method type so that an RSA public key can
// never be used as an HMAC secret (algorithm confusion).
func (a *Authenticator) keyFunc(t *jwt.Token) (any, error) {
	switch t.Method.(type) {
	case *jwt.SigningMethodHMAC:
		if a.hsSecret == nil || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return a.hsSecret, nil
	case *jwt.SigningMethodRSA:
		if a.rsKey == nil || t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return a.rsKey, nil
	default:
		return nil, errors.New("unexpected signing method")
	}
}

// HashKey returns the hex SHA-256 digest of an API key, the format expected
// by the key_sha256 config field.
func HashKey(k string) string {
	d := sha256.Sum256([]byte(k))
	return hex.EncodeToString(d[:])
}
