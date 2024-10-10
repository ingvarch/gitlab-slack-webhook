package logger_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
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

func TestInitLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		logLevel string
	}{
		{"Debug level", "debug"},
		{"Info level", "info"},
		{"Warn level", "warn"},
		{"Error level", "error"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			cfg := &config.Config{
				Port:     "8080",
				LogLevel: "info",
				Slack: &config.SlackConfig{
					BotToken:  "mock-bot-token",
					ChannelID: "mock-channel-id",
				},
				Gitlab: &config.GitlabConfig{
					SecretToken: "mock-secret-token",
					APIToken:    "mock-api-token",
				},
			}

			// Redirect log output to buffer for testing
			logger.InitLogger(cfg)

			testLogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level:     logger.GetLogLevel(testCase.logLevel),
				AddSource: true,
				ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
					return attr
				},
			}))
			slog.SetDefault(testLogger)

			// Logging at all levels
			testLogger.Debug("debug message")
			testLogger.Info("info message")
			testLogger.Warn("warn message")
			testLogger.Error("error message")

			processLogMessages(t, &buf, testCase.logLevel)
		})
	}
}

func processLogMessages(t *testing.T, buf *bytes.Buffer, logLevel string) {
	t.Helper()

	scanner := bufio.NewScanner(buf)
	messageCount := make(map[string]int)
	var allMessages []string

	for scanner.Scan() {
		line := scanner.Text()
		allMessages = append(allMessages, line)

		var logEntry map[string]interface{}
		err := json.Unmarshal([]byte(line), &logEntry)
		if err != nil {
			t.Fatalf("Failed to unmarshal log output: %v", err)
		}

		level, ok := logEntry["level"].(string)
		if !ok {
			t.Errorf("Log level not found or not a string")

			continue
		}

		messageCount[strings.ToLower(level)]++
		t.Logf("Processed message: Level=%s, Content=%s", level, logEntry["msg"])
	}

	t.Logf("Message counts: %v", messageCount)

	expectedMessageCount := map[string]int{
		"debug": 4,
		"info":  3,
		"warn":  2,
		"error": 1,
	}

	expectedCount := expectedMessageCount[logLevel]

	actualCount := 0
	for level, count := range messageCount {
		if shouldLog(logLevel, level) {
			actualCount += count
		}
	}

	if actualCount != expectedCount {
		t.Errorf("Expected %d messages for log level %s, but got %d. All messages:\n%s",
			expectedCount, logLevel, actualCount, strings.Join(allMessages, "\n"))
	} else {
		t.Logf("Found expected number of messages (%d) for log level %s", actualCount, logLevel)
	}
}

func shouldLog(currentLevel, messageLevel string) bool {
	levels := map[string]int{
		"debug": 1,
		"info":  2,
		"warn":  3,
		"error": 4,
	}

	return levels[messageLevel] >= levels[currentLevel]
}
