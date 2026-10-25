// Package gateway implements the MCP security gateway: an authenticating,
// policy-enforcing, rate-limiting reverse proxy for MCP servers that speak
// the Streamable HTTP transport.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/neerajsinghi/mcp-gateway/internal/auth"
	"github.com/neerajsinghi/mcp-gateway/internal/config"
	"github.com/neerajsinghi/mcp-gateway/internal/jsonrpc"
	"github.com/neerajsinghi/mcp-gateway/internal/policy"
	"github.com/neerajsinghi/mcp-gateway/internal/ratelimit"
)

// Audit decisions recorded in the audit log and on trace spans.
const (
	DecisionAllow           = "allow"
	DecisionDeny            = "deny"
	DecisionRateLimited     = "rate_limited"
	DecisionUnauthenticated = "unauthenticated"
	DecisionBadRequest      = "bad_request"
	DecisionUpstreamError   = "upstream_error"
)

// credentialHeaders are credentials for the gateway itself and must never be
// forwarded to an upstream.
var credentialHeaders = []string{"Authorization", "X-API-Key", "Cookie", "Proxy-Authorization"}

// Options customise a Gateway beyond what the config file expresses.
type Options struct {
	// AuditLogger receives one structured record per request. Defaults to
	// a JSON slog logger on stdout.
	AuditLogger *slog.Logger
	// Tracer creates spans. Defaults to the global OpenTelemetry tracer,
	// which is a no-op unless tracing has been configured.
	Tracer trace.Tracer
	// Transport is the base upstream transport, mainly for tests.
	Transport http.RoundTripper
}

// Gateway is an http.Handler that fronts one or more MCP upstreams.
type Gateway struct {
	mux      *http.ServeMux
	auth     *auth.Authenticator
	policies *policy.Engine
	limiter  *ratelimit.Limiter
	audit    *slog.Logger
	tracer   trace.Tracer
	maxBody  int64
}

// New builds a Gateway from a validated configuration.
func New(cfg *config.Config, opts Options) (*Gateway, error) {
	a, err := auth.New(cfg.Auth)
	if err != nil {
		return nil, err
	}
	g := &Gateway{
		mux:      http.NewServeMux(),
		auth:     a,
		policies: policy.NewEngine(cfg),
		limiter:  ratelimit.New(),
		audit:    opts.AuditLogger,
		tracer:   opts.Tracer,
		maxBody:  cfg.MaxBodyBytes,
	}
	if g.audit == nil {
		g.audit = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if g.tracer == nil {
		g.tracer = otel.Tracer("github.com/neerajsinghi/mcp-gateway")
	}
	g.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	for _, u := range cfg.Upstreams {
		h, err := g.newUpstreamHandler(u, opts.Transport)
		if err != nil {
			return nil, err
		}
		g.mux.Handle(u.Path, h)
	}
	return g, nil
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.mux.ServeHTTP(w, r) }

// RunJanitor evicts idle rate-limit buckets every interval until ctx ends.
func (g *Gateway) RunJanitor(ctx context.Context, interval, idle time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.limiter.Sweep(idle)
		}
	}
}

// reqState carries per-request data between the handler and the proxy.
type reqState struct {
	policy         *policy.Policy
	toolsListIDs   map[string]bool
	upstreamStatus int
	toolsHidden    atomic.Int64 // written by the SSE goroutine
}

type stateKey struct{}

type upstreamHandler struct {
	g     *Gateway
	name  string
	proxy *httputil.ReverseProxy
}

func (g *Gateway) newUpstreamHandler(u config.Upstream, base http.RoundTripper) (*upstreamHandler, error) {
	target, err := url.Parse(u.URL)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.Name, err)
	}
	if base == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ResponseHeaderTimeout = u.Timeout.Duration
		base = t
	}
	headers := make(http.Header, len(u.Headers))
	for k, v := range u.Headers {
		headers.Set(k, os.Expand(v, os.Getenv))
	}
	h := &upstreamHandler{g: g, name: u.Name}
	h.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			q := out.URL.RawQuery
			out.URL = cloneURL(target)
			if q != "" {
				if out.URL.RawQuery != "" {
					out.URL.RawQuery += "&" + q
				} else {
					out.URL.RawQuery = q
				}
			}
			out.Host = target.Host
			for _, hdr := range credentialHeaders {
				out.Header.Del(hdr)
			}
			// Let the transport negotiate (and transparently decode)
			// compression so responses can be inspected.
			out.Header.Del("Accept-Encoding")
			for k, v := range headers {
				out.Header[k] = append([]string(nil), v...)
			}
			otel.GetTextMapPropagator().Inject(out.Context(), propagation.HeaderCarrier(out.Header))
		},
		Transport:      base,
		FlushInterval:  -1,
		ModifyResponse: g.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if st, ok := r.Context().Value(stateKey{}).(*reqState); ok {
				st.upstreamStatus = 0
			}
			writeRPCError(w, http.StatusBadGateway, nil, jsonrpc.CodeUpstreamError, "upstream unavailable")
		},
	}
	return h, nil
}

func cloneURL(u *url.URL) *url.URL {
	c := *u
	if u.User != nil {
		uc := *u.User
		c.User = &uc
	}
	return &c
}

// auditRecord accumulates the fields of one audit log entry.
type auditRecord struct {
	identity   string
	authMethod string
	method     string
	tool       string
	batchSize  int
	decision   string
	reason     string
}

func (h *upstreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	g := h.g
	ctx, span := g.tracer.Start(r.Context(), "mcp.gateway "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()

	st := &reqState{}
	rec := &auditRecord{decision: DecisionAllow}
	sw := &statusWriter{ResponseWriter: w}
	r = r.WithContext(context.WithValue(ctx, stateKey{}, st))

	defer func() {
		latency := time.Since(start)
		attrs := []attribute.KeyValue{
			attribute.String("mcp.upstream", h.name),
			attribute.String("mcp.identity", rec.identity),
			attribute.String("mcp.method", rec.method),
			attribute.String("mcp.tool", rec.tool),
			attribute.String("mcp.decision", rec.decision),
			attribute.Int("http.response.status_code", sw.Status()),
		}
		span.SetAttributes(attrs...)
		if rec.decision != DecisionAllow {
			span.SetStatus(codes.Error, rec.decision)
		}
		g.audit.LogAttrs(ctx, slog.LevelInfo, "audit",
			slog.String("upstream", h.name),
			slog.String("identity", rec.identity),
			slog.String("auth_method", rec.authMethod),
			slog.String("http_method", r.Method),
			slog.String("method", rec.method),
			slog.String("tool", rec.tool),
			slog.Int("batch_size", rec.batchSize),
			slog.String("decision", rec.decision),
			slog.String("reason", rec.reason),
			slog.Int("status", sw.Status()),
			slog.Int("upstream_status", st.upstreamStatus),
			slog.Int64("tools_hidden", st.toolsHidden.Load()),
			slog.Float64("latency_ms", float64(latency.Microseconds())/1000),
		)
	}()

	p, err := g.auth.Authenticate(r)
	if err != nil {
		rec.decision, rec.reason = DecisionUnauthenticated, err.Error()
		sw.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway"`)
		writeRPCError(sw, http.StatusUnauthorized, nil, jsonrpc.CodeUnauthorized, "unauthorized")
		return
	}
	rec.identity, rec.authMethod = p.Identity, string(p.Method)
	pol := g.policies.For(p.Identity)
	st.policy = pol

	if rl, ok := pol.RateLimit(); ok {
		if allowed, wait := g.limiter.Allow("identity\x00"+p.Identity, rl.RPS, rl.Burst); !allowed {
			rec.decision, rec.reason = DecisionRateLimited, "identity rate limit"
			setRetryAfter(sw, wait)
			writeRPCError(sw, http.StatusTooManyRequests, nil, jsonrpc.CodeRateLimited, "rate limit exceeded")
			return
		}
	}

	if r.Method == http.MethodPost {
		if !h.inspect(sw, r, p, pol, st, rec) {
			return
		}
	}
	h.proxy.ServeHTTP(sw, r)
	if st.upstreamStatus == 0 && rec.decision == DecisionAllow {
		rec.decision, rec.reason = DecisionUpstreamError, "upstream request failed"
	}
}

// inspect reads and checks the JSON-RPC payload of a POST. It returns false
// when it has already written a rejection.
func (h *upstreamHandler) inspect(w http.ResponseWriter, r *http.Request, p auth.Principal, pol *policy.Policy, st *reqState, rec *auditRecord) bool {
	g := h.g
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.maxBody))
	_ = r.Body.Close()
	if err != nil {
		var mbe *http.MaxBytesError
		rec.decision = DecisionBadRequest
		if errors.As(err, &mbe) {
			rec.reason = "body too large"
			writeRPCError(w, http.StatusRequestEntityTooLarge, nil, jsonrpc.CodeInvalidRequest, "request body too large")
		} else {
			rec.reason = "read body failed"
			writeRPCError(w, http.StatusBadRequest, nil, jsonrpc.CodeInvalidRequest, "could not read request body")
		}
		return false
	}
	msgs, batch, err := jsonrpc.Parse(body)
	if err != nil {
		rec.decision, rec.reason = DecisionBadRequest, "invalid JSON-RPC payload"
		writeRPCError(w, http.StatusBadRequest, nil, jsonrpc.CodeParseError, "parse error")
		return false
	}
	rec.batchSize = len(msgs)
	if len(msgs) == 1 {
		rec.method, rec.tool = msgs[0].Method, msgs[0].ToolName()
	} else {
		rec.method = "batch"
	}

	type rejection struct {
		status int
		code   int
		msg    string
		wait   time.Duration
	}
	var rej *rejection
	var tools []string
	for _, m := range msgs {
		switch m.Method {
		case jsonrpc.MethodToolsCall:
			tool := m.ToolName()
			tools = append(tools, tool)
			if rej != nil {
				continue
			}
			if !pol.AllowsTool(tool) {
				rec.decision, rec.reason = DecisionDeny, "tool not permitted"
				rej = &rejection{status: http.StatusOK, code: jsonrpc.CodeForbidden, msg: fmt.Sprintf("tool %q is not permitted", tool)}
				continue
			}
			if rl, _, ok := pol.ToolRateLimit(tool); ok {
				if allowed, wait := g.limiter.Allow("tool\x00"+p.Identity+"\x00"+tool, rl.RPS, rl.Burst); !allowed {
					rec.decision, rec.reason = DecisionRateLimited, "tool rate limit"
					rej = &rejection{status: http.StatusTooManyRequests, code: jsonrpc.CodeRateLimited, msg: fmt.Sprintf("rate limit exceeded for tool %q", tool), wait: wait}
				}
			}
		case jsonrpc.MethodToolsList:
			if m.IsRequest() {
				if st.toolsListIDs == nil {
					st.toolsListIDs = map[string]bool{}
				}
				st.toolsListIDs[jsonrpc.IDKey(m.ID)] = true
			}
		}
	}
	if batch && len(tools) > 0 {
		rec.tool = strings.Join(tools, ",")
	}
	if rej != nil {
		if rej.wait > 0 {
			setRetryAfter(w, rej.wait)
		}
		if !batch {
			writeRPCError(w, rej.status, msgs[0].ID, rej.code, rej.msg)
			return false
		}
		// A batch is all-or-nothing: answer every request in it with the error.
		var parts [][]byte
		for _, m := range msgs {
			if m.IsRequest() {
				parts = append(parts, jsonrpc.NewError(m.ID, rej.code, rej.msg))
			}
		}
		if len(parts) == 0 {
			parts = append(parts, jsonrpc.NewError(nil, rej.code, rej.msg))
		}
		writeJSON(w, rej.status, append(append([]byte("["), bytes.Join(parts, []byte(","))...), ']'))
		return false
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return true
}

// modifyResponse records the upstream status and hides denied tools in
// tools/list results, for both JSON and SSE responses.
func (g *Gateway) modifyResponse(resp *http.Response) error {
	st, ok := resp.Request.Context().Value(stateKey{}).(*reqState)
	if !ok {
		return nil
	}
	st.upstreamStatus = resp.StatusCode
	if len(st.toolsListIDs) == 0 || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	allow := st.policy.AllowsTool
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		out, n, err := jsonrpc.FilterToolsPayload(body, st.toolsListIDs, allow)
		if err != nil {
			// Not valid JSON: no client can read a tool list from it.
			out, n = body, 0
		}
		st.toolsHidden.Add(int64(n))
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	case "text/event-stream":
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Body = sseTransform(resp.Body, func(payload []byte) []byte {
			out, n, err := jsonrpc.FilterToolsPayload(payload, st.toolsListIDs, allow)
			if err != nil {
				return payload
			}
			st.toolsHidden.Add(int64(n))
			return out
		})
	}
	return nil
}

func setRetryAfter(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	writeJSON(w, status, jsonrpc.NewError(id, code, msg))
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// statusWriter records the response status while preserving flushing via
// Unwrap (used by http.ResponseController and httputil.ReverseProxy).
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush implements http.Flusher.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Status returns the status written so far, or 0.
func (s *statusWriter) Status() int { return s.status }
