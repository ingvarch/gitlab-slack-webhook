package logger_test

import (
	"log/slog"
	"testing"

	"github.com/ingvarch/gitlab-slack-webhook/internal/logger"
)

func TestGetLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{"Debug level", "debug", slog.LevelDebug},
		{"Info level", "info", slog.LevelInfo},
		{"Warn level", "warn", slog.LevelWarn},
		{"Error level", "error", slog.LevelError},
		{"Unknown level", "unknown", slog.LevelDebug},
		{"Empty level", "", slog.LevelDebug},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := logger.GetLogLevel(testCase.level)

			if got != testCase.want {
				t.Errorf("GetLogLevel() = %v, want %v", got, testCase.want)
			}
		})
	}
}
