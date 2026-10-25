package jsonrpc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		n       int
		batch   bool
		wantErr bool
		tool    string
	}{
		{"single call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`, 1, false, false, "x"},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`, 2, true, false, ""},
		{"whitespace", "  \n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}", 1, false, false, ""},
		{"empty", ``, 0, false, true, ""},
		{"empty batch", `[]`, 0, true, true, ""},
		{"garbage", `nope`, 0, false, true, ""},
		{"bad params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"str"}`, 1, false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, batch, err := Parse([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if len(msgs) != tt.n || batch != tt.batch {
				t.Fatalf("got %d msgs batch=%v", len(msgs), batch)
			}
			if tt.n > 0 && msgs[0].ToolName() != tt.tool {
				t.Fatalf("tool = %q, want %q", msgs[0].ToolName(), tt.tool)
			}
		})
	}
}

func TestMessageKinds(t *testing.T) {
	tests := []struct {
		in        string
		req, resp bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"ping"}`, true, false},
		{`{"jsonrpc":"2.0","method":"notifications/x"}`, false, false},
		{`{"jsonrpc":"2.0","id":null,"method":"ping"}`, false, false},
		{`{"jsonrpc":"2.0","id":1,"result":{}}`, false, true},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}`, false, true},
	}
	for _, tt := range tests {
		var m Message
		if err := json.Unmarshal([]byte(tt.in), &m); err != nil {
			t.Fatal(err)
		}
		if m.IsRequest() != tt.req || m.IsResponse() != tt.resp {
			t.Errorf("%s: req=%v resp=%v", tt.in, m.IsRequest(), m.IsResponse())
		}
	}
}

func TestNewError(t *testing.T) {
	tests := []struct {
		id   json.RawMessage
		want string
	}{
		{json.RawMessage(`5`), `{"jsonrpc":"2.0","id":5,"error":{"code":-32003,"message":"no"}}`},
		{json.RawMessage(`"a"`), `{"jsonrpc":"2.0","id":"a","error":{"code":-32003,"message":"no"}}`},
		{nil, `{"jsonrpc":"2.0","id":null,"error":{"code":-32003,"message":"no"}}`},
	}
	for _, tt := range tests {
		if got := string(NewError(tt.id, CodeForbidden, "no")); got != tt.want {
			t.Errorf("got %s, want %s", got, tt.want)
		}
	}
}

func TestFilterToolsPayload(t *testing.T) {
	allow := func(n string) bool { return !strings.HasPrefix(n, "bad") }
	ids := map[string]bool{IDKey(json.RawMessage(`1`)): true, IDKey(json.RawMessage(`"s"`)): true}
	tests := []struct {
		name    string
		in      string
		removed int
		keep    []string
		drop    []string
	}{
		{"filters matching id", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"good"},{"name":"bad_one"}]}}`, 1, []string{"good"}, []string{"bad_one"}},
		{"string id", `{"jsonrpc":"2.0","id":"s","result":{"tools":[{"name":"bad"}]}}`, 1, nil, []string{`"bad"`}},
		{"other id untouched", `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"bad"}]}}`, 0, []string{"bad"}, nil},
		{"notification untouched", `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`, 0, []string{"list_changed"}, nil},
		{"batch", `[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"bad"},{"name":"ok"}]}},{"jsonrpc":"2.0","id":3,"result":{}}]`, 1, []string{"ok", `"id":3`}, []string{`"bad"`}},
		{"tool without name dropped", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"x":1},{"name":"good"}]}}`, 1, []string{"good"}, []string{`"x"`}},
		{"no tools field", `{"jsonrpc":"2.0","id":1,"result":{"other":true}}`, 0, []string{"other"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, n, err := FilterToolsPayload([]byte(tt.in), ids, allow)
			if err != nil {
				t.Fatal(err)
			}
			if n != tt.removed {
				t.Fatalf("removed %d, want %d (%s)", n, tt.removed, out)
			}
			for _, k := range tt.keep {
				if !strings.Contains(string(out), k) {
					t.Errorf("missing %q in %s", k, out)
				}
			}
			for _, d := range tt.drop {
				if strings.Contains(string(out), d) {
					t.Errorf("unexpected %q in %s", d, out)
				}
			}
		})
	}
	if _, _, err := FilterToolsPayload([]byte(`{bad`), ids, allow); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestIDKey(t *testing.T) {
	if IDKey(json.RawMessage(`1`)) != IDKey(json.RawMessage(` 1 `)) {
		t.Fatal("whitespace should not matter")
	}
	if IDKey(json.RawMessage(`1`)) == IDKey(json.RawMessage(`"1"`)) {
		t.Fatal("number and string ids must differ")
	}
}
