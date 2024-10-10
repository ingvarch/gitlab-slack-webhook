package logger

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
)

// InitLogger initializes the logger.
func InitLogger(cfg *config.Config) {
	level := GetLogLevel(cfg.LogLevel)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				if t, ok := attr.Value.Any().(time.Time); ok {
					return slog.String(attr.Key, t.Format("2006-01-02 15:04:05"))
				}
			}

			return attr
		},
	}))
	slog.SetDefault(logger)
}

// GetLogLevel returns the appropriate slog.Level based on the input string.
func GetLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}
