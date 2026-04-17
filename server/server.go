// Package server provides an HTTP server with graceful shutdown, an ASCII banner,
// and structured startup/shutdown logging.
package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rockefeller2021/usuario-auth/logger"
)

// banner is printed to stdout on every server start for easy visual identification.
const banner = `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗███████╗██╗   ██╗ █████╗ ██████╗ ██╗ ██████╗    ║
║   ██║   ██║██╔════╝██║   ██║██╔══██╗██╔══██╗██║██╔═██╗     ║
║   ██║   ██║███████╗██║   ██║███████║██████╔╝██║██║  ██║    ║
║   ██║   ██║╚════██║██║   ██║██╔══██║██╔══██╗██║██║  ██║    ║
║   ╚██████╔╝███████║╚██████╔╝██║  ██║██║  ██║██║╚██████╔╝   ║
║    ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝    ║
║                                                              ║
║          🔐  JWT Auth Library  ·  v1.0.0                     ║
║          github.com/rockefeller2021/usuario-auth             ║
║          Hexagonal Architecture · Go stdlib only             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`

// Config holds all configuration options for the HTTP server.
type Config struct {
	// Port to listen on. Example: "8080".
	Port string
	// ReadTimeout is the maximum duration for reading the request body.
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration
	// IdleTimeout is the maximum duration to keep an idle connection open.
	IdleTimeout time.Duration
}

// DefaultConfig returns a Config with production-safe default timeouts.
func DefaultConfig() Config {
	return Config{
		Port:         "8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Server wraps net/http.Server and adds banner display and graceful shutdown.
type Server struct {
	http *http.Server
	log  *logger.Logger
	cfg  Config
}

// New creates a new Server ready to run.
func New(cfg Config, handler http.Handler, log *logger.Logger) *Server {
	return &Server{
		cfg: cfg,
		log: log,
		http: &http.Server{
			Addr:         ":" + cfg.Port,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
	}
}

// Run prints the banner, starts the HTTP server, and blocks until an OS interrupt
// or SIGTERM is received. It then performs a graceful shutdown with a 10-second timeout.
func (s *Server) Run() error {
	// Print the ASCII banner to stdout (not through the logger so it's always visible)
	fmt.Print(banner)

	s.log.Info("server initializing",
		"addr", s.http.Addr,
		"pid", os.Getpid(),
		"read_timeout", s.cfg.ReadTimeout,
		"write_timeout", s.cfg.WriteTimeout,
	)

	// Channel to capture OS signals for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start the HTTP listener in a goroutine
	errCh := make(chan error, 1)
	go func() {
		s.log.Info(fmt.Sprintf("🚀 Server listening → http://localhost%s", s.http.Addr))
		s.log.Info("Routes available",
			// ── Public ───────────────────────────────
			"POST", "/auth/register",
			"POST", "/auth/login",
			"POST", "/auth/refresh",
			"GET",  "/health",
			// ── Authenticated ─────────────────────────
			"GET",    "/auth/me         (protected: any role)",
			"PUT",    "/users/{id}      (protected: admin | own account)",
			// ── Admin only ───────────────────────────
			"GET",    "/users           (protected: admin)",
			"GET",    "/users/search    (protected: admin) ?email= | ?username=",
			"GET",    "/users/{id}      (protected: admin)",
			"DELETE", "/users/{id}      (protected: admin)",
		)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server listen error: %w", err)
		}
	}()

	// Block until OS signal or server error
	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		s.log.Info("shutdown signal received", "signal", sig.String())
	}

	// Graceful shutdown: allow up to 10 seconds for in-flight requests to complete
	s.log.Info("graceful shutdown in progress...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	s.log.Info("✅ Server stopped cleanly")
	return nil
}
