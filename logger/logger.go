// Package logger provides a structured logging wrapper around Go's log/slog.
// It supports JSON (production) and text (development) formats with configurable log levels.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Level aliases slog.Level for external use without importing log/slog directly.
type Level = slog.Level

// Log level constants exposed from this package.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Config holds options for creating a Logger.
type Config struct {
	// Level is the minimum log level to emit. Default: LevelInfo.
	Level Level
	// Format controls log output: "json" for production, "text" for development.
	Format string
	// Output is the writer for log output. Defaults to os.Stdout.
	Output io.Writer
}

// Logger is a structured logger backed by log/slog.
type Logger struct {
	inner *slog.Logger
}

// New creates a Logger from the given Config.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}

	opts := &slog.HandlerOptions{Level: cfg.Level}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	} else {
		handler = slog.NewTextHandler(cfg.Output, opts)
	}

	return &Logger{inner: slog.New(handler)}
}

// Default returns a Logger with sensible defaults (text format, Info level, stdout).
func Default() *Logger {
	return New(Config{Level: LevelInfo, Format: "text"})
}

// Info logs a message at INFO level with optional key-value pairs.
func (l *Logger) Info(msg string, args ...any) {
	l.inner.Info(msg, args...)
}

// Debug logs a message at DEBUG level with optional key-value pairs.
func (l *Logger) Debug(msg string, args ...any) {
	l.inner.Debug(msg, args...)
}

// Warn logs a message at WARN level with optional key-value pairs.
func (l *Logger) Warn(msg string, args ...any) {
	l.inner.Warn(msg, args...)
}

// Error logs a message at ERROR level with optional key-value pairs.
func (l *Logger) Error(msg string, args ...any) {
	l.inner.Error(msg, args...)
}

// With returns a new Logger with the given key-value pairs pre-attached to every entry.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{inner: l.inner.With(args...)}
}

// WithContext is a no-op placeholder for future context-aware log enrichment
// (e.g., extracting trace IDs from context).
func (l *Logger) WithContext(_ context.Context) *Logger {
	return l
}
