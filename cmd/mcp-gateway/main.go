// Command mcp-gateway runs a security gateway in front of MCP servers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neerajsinghi/mcp-gateway/internal/auth"
	"github.com/neerajsinghi/mcp-gateway/internal/config"
	"github.com/neerajsinghi/mcp-gateway/internal/gateway"
	"github.com/neerajsinghi/mcp-gateway/internal/telemetry"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-gateway:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	cfgPath := fs.String("config", "mcp-gateway.yaml", "path to the YAML config file")
	validate := fs.Bool("validate", false, "validate the config and exit")
	hashKey := fs.String("hash-key", "", "print the key_sha256 value for an API key read from this environment variable, then exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *hashKey != "" {
		v := os.Getenv(*hashKey)
		if v == "" {
			return fmt.Errorf("environment variable %s is empty", *hashKey)
		}
		fmt.Println(auth.HashKey(v))
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *validate {
		fmt.Println("config OK")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := telemetry.Setup(ctx, cfg.Tracing, version)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(sctx)
	}()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	gw, err := gateway.New(cfg, gateway.Options{AuditLogger: logger})
	if err != nil {
		return err
	}
	go gw.RunJanitor(ctx, time.Minute, time.Hour)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           gw,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No ReadTimeout/WriteTimeout: SSE responses are long-lived streams
		// and a connection read deadline would cancel them.
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "upstreams", len(cfg.Upstreams), "version", version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			return err
		}
	}
	return nil
}
