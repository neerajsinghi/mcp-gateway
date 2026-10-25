package gateway

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestSSETransform(t *testing.T) {
	upper := func(b []byte) []byte { return bytes.ToUpper(b) }
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"single event", "data: abc\n\n", "data: ABC\n\n"},
		{"crlf", "data: abc\r\n\r\n", "data: ABC\n\n"},
		{"keeps fields", "event: message\nid: 7\ndata: x\n\n", "event: message\nid: 7\ndata: X\n\n"},
		{"multi-line data joined", "data: a\ndata: b\n\n", "data: A\ndata: B\n\n"},
		{"comment only", ": ping\n\n", ": ping\n\n"},
		{"no space after colon", "data:x\n\n", "data: X\n\n"},
		{"unterminated tail", "data: a\n\ndata: b", "data: A\n\ndata: B\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sseTransform(io.NopCloser(strings.NewReader(tt.in)), upper)
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
