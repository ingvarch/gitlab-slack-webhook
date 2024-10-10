// internal/config/types.go

package config

type Config struct {
	Port     string `env:"APP_PORT"`
	LogLevel string `env:"LOG_LEVEL"`
	Slack    *SlackConfig
	Gitlab   *GitlabConfig
}

type SlackConfig struct {
	BotToken  string `env:"SLACK_BOT_TOKEN"`
	ChannelID string `env:"SLACK_CHANNEL_ID"`
}

type GitlabConfig struct {
	SecretToken string `env:"GITLAB_SECRET_TOKEN"`
	APIToken    string `env:"GITLAB_API_TOKEN"`
}
