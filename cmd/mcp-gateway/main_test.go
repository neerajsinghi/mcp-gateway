package main

import (
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	t.Setenv("DEMO_KEY", "abc")
	example := filepath.Join("..", "..", "examples", "mcp-gateway.yaml")
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"version", []string{"-version"}, false},
		{"hash key", []string{"-hash-key", "DEMO_KEY"}, false},
		{"hash key empty env", []string{"-hash-key", "MCP_GATEWAY_UNSET_VAR"}, true},
		{"validate example", []string{"-config", example, "-validate"}, false},
		{"missing config", []string{"-config", "/nonexistent.yaml"}, true},
		{"bad flag", []string{"-nope"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := run(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("run(%v) err = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}
