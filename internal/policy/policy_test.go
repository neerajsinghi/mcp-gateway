package policy

import (
	"testing"

	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

func engine() *Engine {
	return NewEngine(&config.Config{
		Policies: map[string]config.Policy{
			"ro": {
				AllowTools: []string{"get_*", "search_*", "delete_*"},
				DenyTools:  []string{"delete_*"},
				RateLimit:  &config.RateLimit{RPS: 1, Burst: 2},
				ToolRateLimits: map[string]config.RateLimit{
					"search_*":    {RPS: 1, Burst: 1},
					"search_code": {RPS: 5, Burst: 5},
				},
			},
			"all": {AllowTools: []string{"*"}},
		},
		Bindings:      map[string]string{"alice": "ro", "root": "all"},
		DefaultPolicy: "",
	})
}

func TestAllowsTool(t *testing.T) {
	e := engine()
	tests := []struct {
		identity, tool string
		want           bool
	}{
		{"alice", "get_file", true},
		{"alice", "search_issues", true},
		{"alice", "delete_repo", false},
		{"alice", "run_shell", false},
		{"alice", "", false},
		{"root", "anything", true},
		{"root", "", false},
		{"nobody", "get_file", false},
	}
	for _, tt := range tests {
		t.Run(tt.identity+"/"+tt.tool, func(t *testing.T) {
			if got := e.For(tt.identity).AllowsTool(tt.tool); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultPolicy(t *testing.T) {
	e := NewEngine(&config.Config{
		Policies:      map[string]config.Policy{"base": {AllowTools: []string{"ping"}}},
		DefaultPolicy: "base",
	})
	if !e.For("anyone").AllowsTool("ping") {
		t.Fatal("default policy not applied")
	}
}

func TestToolRateLimit(t *testing.T) {
	p := engine().For("alice")
	tests := []struct {
		tool    string
		wantPat string
		ok      bool
	}{
		{"search_code", "search_*", true}, // lexical order: "search_*" < "search_code"
		{"search_x", "search_*", true},
		{"get_file", "", false},
	}
	for _, tt := range tests {
		_, pat, ok := p.ToolRateLimit(tt.tool)
		if ok != tt.ok || pat != tt.wantPat {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", tt.tool, pat, ok, tt.wantPat, tt.ok)
		}
	}
	if rl, ok := p.RateLimit(); !ok || rl.Burst != 2 {
		t.Fatalf("identity rate limit = %+v %v", rl, ok)
	}
	if _, ok := engine().For("root").RateLimit(); ok {
		t.Fatal("root should have no rate limit")
	}
}
