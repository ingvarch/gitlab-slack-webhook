package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
	"github.com/ingvarch/gitlab-slack-webhook/internal/server"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	t.Parallel()

	// Create a mock config
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

	// Create a new server
	app := server.NewServer(cfg)

	// Create a test request to the root path
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	})

	// Check that the status code is 200 OK
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Check the response body
	require.Equal(t, "GitLab-Slack Webhook Server is running!", string(body))
}
