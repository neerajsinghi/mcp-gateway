// Package config loads and validates the mcp-gateway YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of the gateway configuration file.
type Config struct {
	// Listen is the address the gateway binds to, e.g. ":8080".
	Listen string `yaml:"listen"`
	// MaxBodyBytes caps the size of an incoming JSON-RPC request body.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
	// Upstreams are the MCP servers the gateway fronts.
	Upstreams []Upstream `yaml:"upstreams"`
	// Auth configures how callers are authenticated.
	Auth Auth `yaml:"auth"`
	// Policies maps a policy name to its rules.
	Policies map[string]Policy `yaml:"policies"`
	// Bindings maps an identity to a policy name.
	Bindings map[string]string `yaml:"bindings"`
	// DefaultPolicy is applied to authenticated identities without a binding.
	// When empty, unbound identities are denied every tool.
	DefaultPolicy string `yaml:"default_policy"`
	// Tracing configures optional OpenTelemetry tracing.
	Tracing Tracing `yaml:"tracing"`
}

// Upstream is a single MCP server reachable over Streamable HTTP.
type Upstream struct {
	// Name identifies the upstream in logs and policies.
	Name string `yaml:"name"`
	// URL is the upstream MCP endpoint, e.g. http://localhost:9000/mcp.
	URL string `yaml:"url"`
	// Path is the gateway path that is proxied to URL. Defaults to /mcp/<name>.
	Path string `yaml:"path"`
	// Headers are added to every upstream request. Values may reference
	// environment variables as ${VAR}.
	Headers map[string]string `yaml:"headers"`
	// Timeout bounds the time to receive upstream response headers.
	Timeout Duration `yaml:"timeout"`
}

// Auth groups the supported authentication mechanisms.
type Auth struct {
	// APIKeys are static keys, each mapped to an identity.
	APIKeys []APIKey `yaml:"api_keys"`
	// JWT configures bearer-token verification. Nil disables JWT auth.
	JWT *JWT `yaml:"jwt"`
}

// APIKey binds a static secret to an identity. Exactly one of KeyEnv or
// KeySHA256 must be set so that plaintext secrets never live in the file.
type APIKey struct {
	// Identity is the caller name used for policy lookup and audit.
	Identity string `yaml:"identity"`
	// KeyEnv names an environment variable holding the plaintext key.
	KeyEnv string `yaml:"key_env"`
	// KeySHA256 is the hex-encoded SHA-256 digest of the key.
	KeySHA256 string `yaml:"key_sha256"`
}

// JWT configures verification of HS256 and RS256 bearer tokens.
type JWT struct {
	// Issuer, when set, must match the "iss" claim.
	Issuer string `yaml:"issuer"`
	// Audience, when set, must be present in the "aud" claim.
	Audience string `yaml:"audience"`
	// HS256SecretEnv names an environment variable holding the HMAC secret.
	HS256SecretEnv string `yaml:"hs256_secret_env"`
	// RS256PublicKeyFile is a PEM file containing an RSA public key.
	RS256PublicKeyFile string `yaml:"rs256_public_key_file"`
	// IdentityClaim is the claim used as identity. Defaults to "sub".
	IdentityClaim string `yaml:"identity_claim"`
	// Leeway tolerates clock skew when validating exp/nbf/iat.
	Leeway Duration `yaml:"leeway"`
}

// Policy describes what an identity may do.
type Policy struct {
	// AllowTools are glob patterns (path.Match syntax) of permitted tools.
	AllowTools []string `yaml:"allow_tools"`
	// DenyTools are glob patterns that override AllowTools.
	DenyTools []string `yaml:"deny_tools"`
	// RateLimit applies to every JSON-RPC message sent by the identity.
	RateLimit *RateLimit `yaml:"rate_limit"`
	// ToolRateLimits applies per tool; keys are glob patterns and the
	// first matching pattern (in sorted order) wins.
	ToolRateLimits map[string]RateLimit `yaml:"tool_rate_limits"`
}

// RateLimit is a token-bucket specification.
type RateLimit struct {
	// RPS is the sustained refill rate in tokens per second.
	RPS float64 `yaml:"rps"`
	// Burst is the bucket capacity.
	Burst int `yaml:"burst"`
}

// Tracing configures the OpenTelemetry OTLP/HTTP trace exporter.
type Tracing struct {
	// Enabled turns tracing on. Off by default.
	Enabled bool `yaml:"enabled"`
	// Endpoint is the OTLP/HTTP collector host:port, e.g. localhost:4318.
	Endpoint string `yaml:"endpoint"`
	// Insecure disables TLS to the collector.
	Insecure bool `yaml:"insecure"`
	// ServiceName is reported as service.name. Defaults to mcp-gateway.
	ServiceName string `yaml:"service_name"`
	// SampleRatio is the fraction of traces sampled, 0..1. Defaults to 1.
	SampleRatio *float64 `yaml:"sample_ratio"`
}

// Duration is a time.Duration that unmarshals from strings like "30s".
type Duration struct{ time.Duration }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// DefaultMaxBodyBytes is used when MaxBodyBytes is unset.
const DefaultMaxBodyBytes = 1 << 20

// Load reads, parses, defaults and validates the configuration at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(b)
}

// Parse decodes YAML bytes into a validated Config. Unknown fields are
// rejected to catch typos in security-relevant settings.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Path == "" {
			u.Path = "/mcp/" + u.Name
		}
		if u.Timeout.Duration == 0 {
			u.Timeout.Duration = 30 * time.Second
		}
	}
	if c.Auth.JWT != nil && c.Auth.JWT.IdentityClaim == "" {
		c.Auth.JWT.IdentityClaim = "sub"
	}
	if c.Tracing.ServiceName == "" {
		c.Tracing.ServiceName = "mcp-gateway"
	}
}

// Validate reports every configuration problem it finds.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if len(c.Upstreams) == 0 {
		add("at least one upstream is required")
	}
	names, paths := map[string]bool{}, map[string]bool{}
	for i, u := range c.Upstreams {
		if u.Name == "" {
			add("upstreams[%d]: name is required", i)
		}
		if names[u.Name] {
			add("upstreams[%d]: duplicate name %q", i, u.Name)
		}
		names[u.Name] = true
		pu, err := url.Parse(u.URL)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			add("upstreams[%d]: url must be an absolute http(s) URL", i)
		}
		if !strings.HasPrefix(u.Path, "/") || u.Path == "/healthz" || strings.ContainsAny(u.Path, "{} \t") {
			add("upstreams[%d]: path %q must start with /, contain no spaces or braces, and not be /healthz", i, u.Path)
		}
		if paths[u.Path] {
			add("upstreams[%d]: duplicate path %q", i, u.Path)
		}
		paths[u.Path] = true
	}

	if len(c.Auth.APIKeys) == 0 && c.Auth.JWT == nil {
		add("auth: configure api_keys and/or jwt")
	}
	for i, k := range c.Auth.APIKeys {
		if k.Identity == "" {
			add("auth.api_keys[%d]: identity is required", i)
		}
		if (k.KeyEnv == "") == (k.KeySHA256 == "") {
			add("auth.api_keys[%d]: set exactly one of key_env or key_sha256", i)
		}
		if k.KeySHA256 != "" && !isHex(k.KeySHA256, 64) {
			add("auth.api_keys[%d]: key_sha256 must be 64 hex characters", i)
		}
	}
	if j := c.Auth.JWT; j != nil && j.HS256SecretEnv == "" && j.RS256PublicKeyFile == "" {
		add("auth.jwt: set hs256_secret_env and/or rs256_public_key_file")
	}

	for name, p := range c.Policies {
		for _, pat := range append(append([]string{}, p.AllowTools...), p.DenyTools...) {
			if _, err := path.Match(pat, ""); err != nil {
				add("policies.%s: bad pattern %q", name, pat)
			}
		}
		if p.RateLimit != nil {
			if err := p.RateLimit.validate(); err != nil {
				add("policies.%s.rate_limit: %v", name, err)
			}
		}
		for pat, rl := range p.ToolRateLimits {
			if _, err := path.Match(pat, ""); err != nil {
				add("policies.%s.tool_rate_limits: bad pattern %q", name, pat)
			}
			if err := rl.validate(); err != nil {
				add("policies.%s.tool_rate_limits[%s]: %v", name, pat, err)
			}
		}
	}
	for id, pol := range c.Bindings {
		if _, ok := c.Policies[pol]; !ok {
			add("bindings.%s: unknown policy %q", id, pol)
		}
	}
	if c.DefaultPolicy != "" {
		if _, ok := c.Policies[c.DefaultPolicy]; !ok {
			add("default_policy: unknown policy %q", c.DefaultPolicy)
		}
	}
	if c.Tracing.Enabled && c.Tracing.Endpoint == "" {
		add("tracing: endpoint is required when enabled")
	}
	if r := c.Tracing.SampleRatio; r != nil && (*r < 0 || *r > 1) {
		add("tracing: sample_ratio must be between 0 and 1")
	}
	return errors.Join(errs...)
}

func (r RateLimit) validate() error {
	if r.RPS <= 0 || r.Burst <= 0 {
		return errors.New("rps and burst must be positive")
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}
