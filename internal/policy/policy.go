// Package policy decides which MCP tools an identity may see and call.
package policy

import (
	"path"
	"sort"

	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

// Policy is a compiled set of tool rules and rate limits.
type Policy struct {
	// Name is the policy name from configuration ("" for the deny-all policy).
	Name      string
	allow     []string
	deny      []string
	rateLimit *config.RateLimit
	toolPats  []string
	toolRates map[string]config.RateLimit
}

// AllowsTool reports whether tool is permitted. Deny patterns take
// precedence over allow patterns; a tool matching no allow pattern is denied.
func (p *Policy) AllowsTool(tool string) bool {
	if p == nil || tool == "" {
		return false
	}
	for _, pat := range p.deny {
		if ok, _ := path.Match(pat, tool); ok {
			return false
		}
	}
	for _, pat := range p.allow {
		if ok, _ := path.Match(pat, tool); ok {
			return true
		}
	}
	return false
}

// RateLimit returns the per-identity rate limit, if any.
func (p *Policy) RateLimit() (config.RateLimit, bool) {
	if p == nil || p.rateLimit == nil {
		return config.RateLimit{}, false
	}
	return *p.rateLimit, true
}

// ToolRateLimit returns the rate limit for tool and the pattern that
// matched it. Patterns are evaluated in lexical order for determinism.
func (p *Policy) ToolRateLimit(tool string) (config.RateLimit, string, bool) {
	if p == nil {
		return config.RateLimit{}, "", false
	}
	for _, pat := range p.toolPats {
		if ok, _ := path.Match(pat, tool); ok {
			return p.toolRates[pat], pat, true
		}
	}
	return config.RateLimit{}, "", false
}

// Engine resolves identities to policies.
type Engine struct {
	policies map[string]*Policy
	bindings map[string]string
	def      *Policy
}

// denyAll is used for identities with neither a binding nor a default.
var denyAll = &Policy{}

// NewEngine compiles the policies, bindings and default from cfg. The
// configuration is assumed to be validated.
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{policies: map[string]*Policy{}, bindings: map[string]string{}}
	for name, p := range cfg.Policies {
		cp := &Policy{
			Name:      name,
			allow:     append([]string(nil), p.AllowTools...),
			deny:      append([]string(nil), p.DenyTools...),
			toolRates: map[string]config.RateLimit{},
		}
		if p.RateLimit != nil {
			rl := *p.RateLimit
			cp.rateLimit = &rl
		}
		for pat, rl := range p.ToolRateLimits {
			cp.toolPats = append(cp.toolPats, pat)
			cp.toolRates[pat] = rl
		}
		sort.Strings(cp.toolPats)
		e.policies[name] = cp
	}
	for id, pol := range cfg.Bindings {
		e.bindings[id] = pol
	}
	e.def = denyAll
	if p, ok := e.policies[cfg.DefaultPolicy]; ok {
		e.def = p
	}
	return e
}

// For returns the policy that applies to identity. It never returns nil.
func (e *Engine) For(identity string) *Policy {
	if name, ok := e.bindings[identity]; ok {
		if p, ok := e.policies[name]; ok {
			return p
		}
	}
	return e.def
}
