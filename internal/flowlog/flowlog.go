// Package flowlog provides the small, security-safe structured logging seam
// used by the demo services. Callers choose explicit attributes; credentials
// and compact tokens must never be passed to Event or Error.
package flowlog

import (
	"log/slog"
	"os"
)

// Logger emits one-line JSON records that can be correlated by the txn field.
type Logger struct {
	logger *slog.Logger
}

func New(service string) *Logger {
	return &Logger{logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", service)}
}

func (l *Logger) Event(name string, attributes ...any) {
	if l != nil && l.logger != nil {
		l.logger.Info("flow", append([]any{"event", name}, attributes...)...)
	}
}

func (l *Logger) Error(name string, err error, attributes ...any) {
	if l == nil || l.logger == nil {
		return
	}
	fields := []any{"event", name, "error", err}
	fields = append(fields, attributes...)
	l.logger.Error("flow", fields...)
}
