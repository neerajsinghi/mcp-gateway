package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/neerajsinghi/mcp-gateway/internal/auth"
	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

const (
	adminKey  = "admin-key-0123456789"
	readerKey = "reader-key-0123456789"
	jwtSecret = "0123456789abcdef0123456789abcdef"
)

var toolsListBody = `{"jsonrpc":"2.0","id":%s,"result":{"tools":[` +
	`{"name":"search_code","description":"search"},` +
	`{"name":"get_file"},` +
	`{"name":"delete_repo"}],"nextCursor":"abc"}}`

// fakeUpstream is a minimal MCP server that records what it receives.
type fakeUpstream struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	sse      bool
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Clone(r.Context()))
	f.bodies = append(f.bodies, string(b))
	sse := f.sse
	f.mu.Unlock()

	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(b, &msg)
	var resp string
	switch msg.Method {
	case "tools/list":
		resp = fmt.Sprintf(toolsListBody, msg.ID)
	case "":
		resp = `{"jsonrpc":"2.0","id":null,"result":{}}`
	default:
		resp = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, msg.ID)
	}
	w.Header().Set("Mcp-Session-Id", "sess-1")
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\n")
		fmt.Fprint(w, "event: message\nid: 1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
		fmt.Fprintf(w, "event: message\nid: 2\ndata: %s\n\n", resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
}

func (f *fakeUpstream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

type harness struct {
	gw    *Gateway
	srv   *httptest.Server
	up    *fakeUpstream
	audit *bytes.Buffer
}

func newHarness(t *testing.T, sse bool) *harness {
	t.Helper()
	up := &fakeUpstream{sse: sse}
	upSrv := httptest.NewServer(up)
	t.Cleanup(upSrv.Close)

	t.Setenv("TEST_ADMIN_KEY", adminKey)
	t.Setenv("TEST_JWT_SECRET", jwtSecret)
	t.Setenv("TEST_UPSTREAM_TOKEN", "upstream-secret")
	yaml := fmt.Sprintf(`
upstreams:
  - name: fake
    url: %s/mcp
    headers:
      Authorization: "Bearer ${TEST_UPSTREAM_TOKEN}"
auth:
  api_keys:
    - identity: admin
      key_env: TEST_ADMIN_KEY
    - identity: reader
      key_sha256: %s
  jwt:
    issuer: test-issuer
    hs256_secret_env: TEST_JWT_SECRET
policies:
  full:
    allow_tools: ["*"]
  readonly:
    allow_tools: ["search_*", "get_*", "delete_*"]
    deny_tools: ["delete_*"]
    rate_limit: {rps: 0.001, burst: 5}
    tool_rate_limits:
      search_*: {rps: 0.001, burst: 2}
bindings:
  admin: full
  reader: readonly
  jwt-user: readonly
`, upSrv.URL, auth.HashKey(readerKey))
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	var buf bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(&lockedWriter{w: &buf, mu: &mu}, nil))
	gw, err := New(cfg, Options{AuditLogger: logger})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	return &harness{gw: gw, srv: srv, up: up, audit: &buf}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (h *harness) post(t *testing.T, auth, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp/fake", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func call(id int, tool string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, id, tool)
}

func rpcErrorCode(t *testing.T, body string) int {
	t.Helper()
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if r.Error == nil {
		return 0
	}
	return r.Error.Code
}

func signHS(t *testing.T, claims jwt.MapClaims, secret string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuthRejection(t *testing.T) {
	h := newHarness(t, false)
	now := time.Now()
	tests := []struct {
		name string
		auth string
	}{
		{"missing", ""},
		{"wrong api key", "nope"},
		{"jwt wrong secret", signHS(t, jwt.MapClaims{"sub": "jwt-user", "iss": "test-issuer", "exp": now.Add(time.Hour).Unix()}, "another-secret-another-secret-xx")},
		{"jwt expired", signHS(t, jwt.MapClaims{"sub": "jwt-user", "iss": "test-issuer", "exp": now.Add(-time.Hour).Unix()}, jwtSecret)},
		{"jwt wrong issuer", signHS(t, jwt.MapClaims{"sub": "jwt-user", "iss": "evil", "exp": now.Add(time.Hour).Unix()}, jwtSecret)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := h.post(t, tt.auth, call(1, "get_file"))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if got := rpcErrorCode(t, body); got != -32001 {
				t.Fatalf("code = %d, want -32001", got)
			}
			if resp.Header.Get("WWW-Authenticate") == "" {
				t.Fatal("missing WWW-Authenticate")
			}
		})
	}
	if n := h.up.count(); n != 0 {
		t.Fatalf("upstream received %d requests, want 0", n)
	}
}

func TestAllowedCallPassthrough(t *testing.T) {
	h := newHarness(t, false)
	tok := signHS(t, jwt.MapClaims{"sub": "jwt-user", "iss": "test-issuer", "exp": time.Now().Add(time.Hour).Unix()}, jwtSecret)
	tests := []struct {
		name string
		auth string
		tool string
	}{
		{"api key env", adminKey, "delete_repo"},
		{"api key sha256", readerKey, "get_file"},
		{"jwt", tok, "get_file"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := call(i+10, tt.tool)
			resp, got := h.post(t, tt.auth, body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d body=%s", resp.StatusCode, got)
			}
			if !strings.Contains(got, `"text":"ok"`) || rpcErrorCode(t, got) != 0 {
				t.Fatalf("unexpected body %s", got)
			}
			if resp.Header.Get("Mcp-Session-Id") != "sess-1" {
				t.Fatal("session header not passed through")
			}
			h.up.mu.Lock()
			last := h.up.requests[len(h.up.requests)-1]
			lastBody := h.up.bodies[len(h.up.bodies)-1]
			h.up.mu.Unlock()
			if lastBody != body {
				t.Fatalf("upstream body = %q, want %q", lastBody, body)
			}
			if a := last.Header.Get("Authorization"); a != "Bearer upstream-secret" {
				t.Fatalf("upstream Authorization = %q; client credentials must be replaced", a)
			}
		})
	}
}

func TestToolDenied(t *testing.T) {
	h := newHarness(t, false)
	tests := []struct {
		name string
		tool string
	}{
		{"deny pattern wins", "delete_repo"},
		{"not in allowlist", "run_shell"},
		{"empty tool", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := h.post(t, readerKey, call(7, tt.tool))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if got := rpcErrorCode(t, body); got != -32003 {
				t.Fatalf("code = %d, want -32003 (body %s)", got, body)
			}
			if !strings.Contains(body, `"id":7`) {
				t.Fatalf("error must echo request id: %s", body)
			}
		})
	}
	if n := h.up.count(); n != 0 {
		t.Fatalf("denied calls reached upstream %d times", n)
	}
}

func TestUnboundIdentityDeniedByDefault(t *testing.T) {
	h := newHarness(t, false)
	tok := signHS(t, jwt.MapClaims{"sub": "stranger", "iss": "test-issuer", "exp": time.Now().Add(time.Hour).Unix()}, jwtSecret)
	_, body := h.post(t, tok, call(1, "get_file"))
	if got := rpcErrorCode(t, body); got != -32003 {
		t.Fatalf("code = %d, want -32003", got)
	}
}

func TestToolsListFiltering(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
			h := newHarness(t, sse)
			tests := []struct {
				name string
				auth string
				want []string
			}{
				{"reader hides denied", readerKey, []string{"search_code", "get_file"}},
				{"admin sees all", adminKey, []string{"search_code", "get_file", "delete_repo"}},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					resp, body := h.post(t, tt.auth, `{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}`)
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status = %d", resp.StatusCode)
					}
					payload := body
					if sse {
						if !strings.Contains(body, ": keepalive") || !strings.Contains(body, "notifications/progress") {
							t.Fatalf("other SSE events must pass through: %q", body)
						}
						payload = lastData(body)
					}
					var msg struct {
						ID     string `json:"id"`
						Result struct {
							Tools []struct {
								Name string `json:"name"`
							} `json:"tools"`
							NextCursor string `json:"nextCursor"`
						} `json:"result"`
					}
					if err := json.Unmarshal([]byte(payload), &msg); err != nil {
						t.Fatalf("decode %q: %v", payload, err)
					}
					var names []string
					for _, tl := range msg.Result.Tools {
						names = append(names, tl.Name)
					}
					if strings.Join(names, ",") != strings.Join(tt.want, ",") {
						t.Fatalf("tools = %v, want %v", names, tt.want)
					}
					if msg.ID != "list-1" || msg.Result.NextCursor != "abc" {
						t.Fatalf("other fields must be preserved: %+v", msg)
					}
				})
			}
		})
	}
}

func lastData(sse string) string {
	var last string
	for _, l := range strings.Split(sse, "\n") {
		if v, ok := strings.CutPrefix(l, "data: "); ok {
			last = v
		}
	}
	return last
}

func TestRateLimit(t *testing.T) {
	t.Run("per tool", func(t *testing.T) {
		h := newHarness(t, false)
		// search_* allows burst 2.
		for i := 0; i < 2; i++ {
			resp, body := h.post(t, readerKey, call(i, "search_code"))
			if resp.StatusCode != http.StatusOK || rpcErrorCode(t, body) != 0 {
				t.Fatalf("call %d: status %d body %s", i, resp.StatusCode, body)
			}
		}
		resp, body := h.post(t, readerKey, call(3, "search_code"))
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", resp.StatusCode)
		}
		if rpcErrorCode(t, body) != -32029 || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("bad rate limit response: %s %v", body, resp.Header)
		}
		// A different tool still has budget.
		if resp, _ := h.post(t, readerKey, call(4, "get_file")); resp.StatusCode != http.StatusOK {
			t.Fatalf("get_file status = %d", resp.StatusCode)
		}
	})
	t.Run("per identity", func(t *testing.T) {
		h := newHarness(t, false)
		// readonly allows burst 5 per identity.
		for i := 0; i < 5; i++ {
			if resp, _ := h.post(t, readerKey, call(i, "get_file")); resp.StatusCode != http.StatusOK {
				t.Fatalf("call %d status = %d", i, resp.StatusCode)
			}
		}
		if resp, _ := h.post(t, readerKey, call(9, "get_file")); resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", resp.StatusCode)
		}
		// Other identities are unaffected.
		if resp, _ := h.post(t, adminKey, call(9, "get_file")); resp.StatusCode != http.StatusOK {
			t.Fatalf("admin status = %d", resp.StatusCode)
		}
	})
}

func TestBatchWithDeniedCallIsRejected(t *testing.T) {
	h := newHarness(t, false)
	body := "[" + call(1, "get_file") + "," + call(2, "delete_repo") + `,{"jsonrpc":"2.0","method":"notifications/initialized"}]`
	resp, got := h.post(t, readerKey, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var errs []struct {
		ID    int `json:"id"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(got), &errs); err != nil {
		t.Fatalf("decode %q: %v", got, err)
	}
	if len(errs) != 2 || errs[0].ID != 1 || errs[1].ID != 2 || errs[1].Error.Code != -32003 {
		t.Fatalf("unexpected batch response %s", got)
	}
	if h.up.count() != 0 {
		t.Fatal("rejected batch reached upstream")
	}
}

func TestBadRequests(t *testing.T) {
	h := newHarness(t, false)
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{"invalid json", `{"jsonrpc":`, http.StatusBadRequest},
		{"empty", ``, http.StatusBadRequest},
		{"empty batch", `[]`, http.StatusBadRequest},
		{"too large", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", 2<<20) + `"}}`, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := h.post(t, adminKey, tt.body)
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, false)
	resp, err := http.Get(h.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "ok") {
		t.Fatalf("healthz: %d %s", resp.StatusCode, b)
	}
}

func TestUpstreamDown(t *testing.T) {
	t.Setenv("K", adminKey)
	cfg, err := config.Parse([]byte(`
upstreams: [{name: dead, url: "http://127.0.0.1:1/mcp"}]
auth: {api_keys: [{identity: admin, key_env: K}]}
policies: {full: {allow_tools: ["*"]}}
bindings: {admin: full}
`))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(cfg, Options{AuditLogger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/dead", strings.NewReader(call(1, "x")))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || rpcErrorCode(t, rec.Body.String()) != -32002 {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuditLog(t *testing.T) {
	h := newHarness(t, false)
	h.post(t, readerKey, call(1, "get_file"))
	h.post(t, readerKey, call(2, "delete_repo"))
	h.post(t, "bogus-secret-value", call(3, "get_file"))

	logs := h.audit.String()
	for _, secret := range []string{readerKey, adminKey, jwtSecret, "bogus-secret-value", "upstream-secret"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("audit log leaked secret %q", secret)
		}
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	want := []struct {
		identity, tool, decision string
		upstream                 float64
	}{
		{"reader", "get_file", DecisionAllow, 200},
		{"reader", "delete_repo", DecisionDeny, 0},
		{"", "", DecisionUnauthenticated, 0},
	}
	for i, w := range want {
		r := recs[i]
		if r["identity"] != w.identity || r["tool"] != w.tool || r["decision"] != w.decision || r["upstream_status"] != w.upstream {
			t.Errorf("record %d = %v, want %+v", i, r, w)
		}
		if _, ok := r["latency_ms"]; !ok {
			t.Errorf("record %d missing latency_ms", i)
		}
	}
}
