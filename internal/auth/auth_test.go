package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

const hsSecret = "0123456789abcdef0123456789abcdef"

func setup(t *testing.T) (*Authenticator, *rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	keyFile := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyFile, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("T_KEY", "plain-key")
	t.Setenv("T_HS", hsSecret)
	a, err := New(config.Auth{
		APIKeys: []config.APIKey{
			{Identity: "env-user", KeyEnv: "T_KEY"},
			{Identity: "hash-user", KeySHA256: HashKey("hashed-key")},
		},
		JWT: &config.JWT{
			Issuer:             "iss",
			Audience:           "mcp",
			HS256SecretEnv:     "T_HS",
			RS256PublicKeyFile: keyFile,
			IdentityClaim:      "sub",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, priv, pubPEM
}

func TestAuthenticate(t *testing.T) {
	a, priv, pubPEM := setup(t)
	exp := time.Now().Add(time.Hour).Unix()
	good := jwt.MapClaims{"sub": "alice", "iss": "iss", "aud": "mcp", "exp": exp}

	sign := func(m jwt.SigningMethod, key any, c jwt.MapClaims) string {
		s, err := jwt.NewWithClaims(m, c).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	with := func(k string, v any) jwt.MapClaims {
		c := jwt.MapClaims{}
		for kk, vv := range good {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	noneTok := sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, good)
	// Algorithm confusion: HMAC-sign with the RSA public key bytes.
	confused := sign(jwt.SigningMethodHS256, pubPEM, good)
	hs512 := sign(jwt.SigningMethodHS512, []byte(hsSecret), good)

	tests := []struct {
		name     string
		headers  map[string]string
		identity string
		method   Method
		err      error
	}{
		{"no credentials", nil, "", "", ErrMissingCredentials},
		{"x-api-key env", map[string]string{"X-API-Key": "plain-key"}, "env-user", MethodAPIKey, nil},
		{"bearer api key hashed", map[string]string{"Authorization": "Bearer hashed-key"}, "hash-user", MethodAPIKey, nil},
		{"lowercase scheme", map[string]string{"Authorization": "bearer hashed-key"}, "hash-user", MethodAPIKey, nil},
		{"wrong key", map[string]string{"X-API-Key": "nope"}, "", "", ErrInvalidCredentials},
		{"basic scheme", map[string]string{"Authorization": "Basic Zm9vOmJhcg=="}, "", "", ErrInvalidCredentials},
		{"empty bearer", map[string]string{"Authorization": "Bearer "}, "", "", ErrInvalidCredentials},
		{"hs256", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), good)}, "alice", MethodJWT, nil},
		{"rs256", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodRS256, priv, good)}, "alice", MethodJWT, nil},
		{"alg none", map[string]string{"Authorization": "Bearer " + noneTok}, "", "", ErrInvalidCredentials},
		{"alg confusion", map[string]string{"Authorization": "Bearer " + confused}, "", "", ErrInvalidCredentials},
		{"hs512 not allowed", map[string]string{"Authorization": "Bearer " + hs512}, "", "", ErrInvalidCredentials},
		{"expired", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), with("exp", time.Now().Add(-time.Minute).Unix()))}, "", "", ErrInvalidCredentials},
		{"no exp", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), with("exp", nil))}, "", "", ErrInvalidCredentials},
		{"wrong audience", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), with("aud", "other"))}, "", "", ErrInvalidCredentials},
		{"wrong issuer", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), with("iss", "x"))}, "", "", ErrInvalidCredentials},
		{"missing sub", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), with("sub", nil))}, "", "", ErrInvalidCredentials},
		{"non-string sub", map[string]string{"Authorization": "Bearer " + sign(jwt.SigningMethodHS256, []byte(hsSecret), with("sub", 42))}, "", "", ErrInvalidCredentials},
		{"garbage jwt", map[string]string{"Authorization": "Bearer a.b.c"}, "", "", ErrInvalidCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPost, "/", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			p, err := a.Authenticate(r)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if p.Identity != tt.identity || p.Method != tt.method {
				t.Fatalf("principal = %+v, want %s/%s", p, tt.identity, tt.method)
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	t.Setenv("SHORT", "short")
	tests := []struct {
		name string
		cfg  config.Auth
	}{
		{"empty env key", config.Auth{APIKeys: []config.APIKey{{Identity: "a", KeyEnv: "DOES_NOT_EXIST_XYZ"}}}},
		{"bad hash", config.Auth{APIKeys: []config.APIKey{{Identity: "a", KeySHA256: "zz"}}}},
		{"short hs secret", config.Auth{JWT: &config.JWT{HS256SecretEnv: "SHORT"}}},
		{"missing key file", config.Auth{JWT: &config.JWT{RS256PublicKeyFile: "/nonexistent/key.pem"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
