package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

func TestSetup(t *testing.T) {
	t.Cleanup(func() { otel.SetTracerProvider(noop.NewTracerProvider()) })
	ratio := 0.5
	tests := []struct {
		name string
		cfg  config.Tracing
	}{
		{"disabled", config.Tracing{}},
		{"enabled", config.Tracing{Enabled: true, Endpoint: "127.0.0.1:1", Insecure: true, ServiceName: "t", SampleRatio: &ratio}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shutdown, err := Setup(context.Background(), tt.cfg, "test")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = shutdown(ctx) // exporting to a closed port may fail; must not hang or panic
		})
	}
}
