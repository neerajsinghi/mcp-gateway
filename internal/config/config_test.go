package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const valid = `
listen: ":9090"
upstreams:
  - name: gh
    url: http://localhost:9000/mcp
    timeout: 5s
auth:
  api_keys:
    - identity: bot
      key_env: BOT_KEY
policies:
  ro:
    allow_tools: ["get_*"]
    rate_limit: {rps: 1, burst: 2}
bindings:
  bot: ro
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9090" || c.Upstreams[0].Path != "/mcp/gh" || c.Upstreams[0].Timeout.Duration != 5*time.Second {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.MaxBodyBytes != DefaultMaxBodyBytes || c.Tracing.ServiceName != "mcp-gateway" {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{"unknown field", func(s string) string { return s + "bogus: 1\n" }, "bogus"},
		{"no upstreams", func(s string) string {
			return strings.Replace(s, "  - name: gh\n    url: http://localhost:9000/mcp\n    timeout: 5s\n", "", 1)
		}, "upstream"},
		{"bad url", func(s string) string { return strings.Replace(s, "http://localhost:9000/mcp", "ftp://x", 1) }, "url"},
		{"bad timeout", func(s string) string { return strings.Replace(s, "5s", "soon", 1) }, "duration"},
		{"unknown policy binding", func(s string) string { return strings.Replace(s, "bot: ro", "bot: nope", 1) }, "unknown policy"},
		{"bad glob", func(s string) string { return strings.Replace(s, `"get_*"`, `"[bad"`, 1) }, "bad pattern"},
		{"bad rate", func(s string) string { return strings.Replace(s, "rps: 1", "rps: 0", 1) }, "positive"},
		{"no secret source", func(s string) string { return strings.Replace(s, "      key_env: BOT_KEY\n", "", 1) }, "exactly one"},
		{"bad sha", func(s string) string { return strings.Replace(s, "key_env: BOT_KEY", "key_sha256: abc", 1) }, "64 hex"},
		{"tracing without endpoint", func(s string) string { return s + "tracing: {enabled: true}\n" }, "endpoint"},
		{"healthz path", func(s string) string { return strings.Replace(s, "    timeout: 5s\n", "    path: /healthz\n", 1) }, "path"},
		{"jwt without keys", func(s string) string { return strings.Replace(s, "auth:\n", "auth:\n  jwt: {issuer: x}\n", 1) }, "jwt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(valid)))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadExample(t *testing.T) {
	p := filepath.Join("..", "..", "examples", "mcp-gateway.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Skip("example config not present")
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("example config invalid: %v", err)
	}
	if _, err := Load("/does/not/exist.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
