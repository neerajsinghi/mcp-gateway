// Package jsonrpc contains the minimal JSON-RPC 2.0 handling the gateway
// needs to inspect MCP traffic: request parsing, error construction and
// rewriting of tools/list results.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Standard and gateway-specific JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeInternalError  = -32603
	// CodeUnauthorized is returned when the caller failed authentication.
	CodeUnauthorized = -32001
	// CodeForbidden is returned when policy denies the request.
	CodeForbidden = -32003
	// CodeRateLimited is returned when a rate limit is exceeded.
	CodeRateLimited = -32029
	// CodeUpstreamError is returned when the upstream cannot be reached.
	CodeUpstreamError = -32002
)

// MCP method names the gateway treats specially.
const (
	MethodToolsCall = "tools/call"
	MethodToolsList = "tools/list"
)

// Message is a JSON-RPC request, notification or response. Only the fields
// the gateway inspects are decoded; the original bytes are kept in Raw.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// IsRequest reports whether m is a request (has a method and an id).
func (m Message) IsRequest() bool { return m.Method != "" && hasID(m.ID) }

// IsResponse reports whether m is a response (no method; result or error).
func (m Message) IsResponse() bool {
	return m.Method == "" && (m.Result != nil || m.Error != nil)
}

func hasID(id json.RawMessage) bool {
	return len(id) > 0 && !bytes.Equal(id, []byte("null"))
}

// ToolName returns params.name for tools/call requests, or "".
func (m Message) ToolName() string {
	if m.Method != MethodToolsCall || len(m.Params) == 0 {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return ""
	}
	return p.Name
}

// ErrEmpty is returned for an empty body or an empty batch.
var ErrEmpty = errors.New("empty JSON-RPC payload")

// Parse decodes a single message or a batch. batch reports whether the
// payload was a JSON array.
func Parse(body []byte) (msgs []Message, batch bool, err error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, false, ErrEmpty
	}
	if body[0] == '[' {
		if err := json.Unmarshal(body, &msgs); err != nil {
			return nil, true, err
		}
		if len(msgs) == 0 {
			return nil, true, ErrEmpty
		}
		return msgs, true, nil
	}
	var m Message
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, false, err
	}
	return []Message{m}, false, nil
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type errorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   Error           `json:"error"`
}

// NewError encodes an error response for id. A missing id is encoded as
// null, as required for errors not tied to a specific request.
func NewError(id json.RawMessage, code int, msg string) []byte {
	if !hasID(id) {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(errorResponse{JSONRPC: "2.0", ID: id, Error: Error{Code: code, Message: msg}})
	return b
}

// FilterToolsResult removes tools for which allow returns false from a
// tools/list result object. It returns the rewritten result, the number of
// tools removed, and leaves unknown fields untouched.
func FilterToolsResult(result json.RawMessage, allow func(string) bool) (json.RawMessage, int, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		return nil, 0, err
	}
	rawTools, ok := obj["tools"]
	if !ok {
		return result, 0, nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return nil, 0, err
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var named struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(t, &named); err == nil && named.Name != "" && allow(named.Name) {
			kept = append(kept, t)
		}
	}
	removed := len(tools) - len(kept)
	if removed == 0 {
		return result, 0, nil
	}
	nb, err := json.Marshal(kept)
	if err != nil {
		return nil, 0, err
	}
	obj["tools"] = nb
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, 0, err
	}
	return out, removed, nil
}

// FilterToolsPayload rewrites a response payload (single message or batch)
// so that tools/list results whose id is in ids only contain allowed
// tools. Payloads that are not JSON-RPC responses are returned unchanged.
func FilterToolsPayload(payload []byte, ids map[string]bool, allow func(string) bool) ([]byte, int, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return payload, 0, nil
	}
	if trimmed[0] == '[' {
		var msgs []json.RawMessage
		if err := json.Unmarshal(trimmed, &msgs); err != nil {
			return nil, 0, err
		}
		total, changed := 0, false
		for i, m := range msgs {
			out, n, err := filterOne(m, ids, allow)
			if err != nil {
				return nil, 0, err
			}
			if n > 0 {
				msgs[i], total, changed = out, total+n, true
			}
		}
		if !changed {
			return payload, 0, nil
		}
		b, err := json.Marshal(msgs)
		return b, total, err
	}
	out, n, err := filterOne(trimmed, ids, allow)
	if err != nil || n == 0 {
		return payload, 0, err
	}
	return out, n, nil
}

func filterOne(raw []byte, ids map[string]bool, allow func(string) bool) ([]byte, int, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, 0, err
	}
	res, ok := obj["result"]
	if !ok || !ids[IDKey(obj["id"])] {
		return raw, 0, nil
	}
	nr, n, err := FilterToolsResult(res, allow)
	if err != nil || n == 0 {
		return raw, 0, err
	}
	obj["result"] = nr
	b, err := json.Marshal(obj)
	return b, n, err
}

// IDKey normalises a JSON-RPC id into a comparable map key.
func IDKey(id json.RawMessage) string {
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return string(id)
	}
	b, _ := json.Marshal(v)
	return string(b)
}
