// internal/config/types.go

package config

type Config struct {
	Port string `env:"APP_PORT"`

	Slack  *SlackConfig
	Gitlab *GitlabConfig
}

type SlackConfig struct {
	BotToken  string `env:"SLACK_BOT_TOKEN"`
	ChannelID string `env:"SLACK_CHANNEL_ID"`
}

type GitlabConfig struct {
	SecretToken bool     `env:"GITLAB_SECRET_TOKEN"`
	ApiToken    []string `env:"GITLAB_API_TOKEN"`
}
