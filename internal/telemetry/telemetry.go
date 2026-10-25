// Package telemetry wires optional OpenTelemetry tracing for the gateway.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/neerajsinghi/mcp-gateway/internal/config"
)

// Shutdown flushes and stops the tracer provider.
type Shutdown func(context.Context) error

// Setup installs a global OTLP/HTTP tracer provider and W3C trace-context
// propagator when tracing is enabled. When disabled it does nothing and the
// global no-op provider stays in place, so instrumentation costs ~nothing.
func Setup(ctx context.Context, c config.Tracing, version string) (Shutdown, error) {
	if !c.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(c.Endpoint)}
	if c.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	ratio := 1.0
	if c.SampleRatio != nil {
		ratio = *c.SampleRatio
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", c.ServiceName),
		attribute.String("service.version", version),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp.Shutdown, nil
}
