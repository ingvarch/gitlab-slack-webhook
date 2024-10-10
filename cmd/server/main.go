package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
	"github.com/ingvarch/gitlab-slack-webhook/internal/logger"
)

func main() {

	// Initialize custom logger
	logger.InitLogger()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Initialize configuration
	cfg, err := config.SetupConfig(ctx)
	if err != nil {
		slog.Error("Configuration setup:", "error", err)
		os.Exit(1)
	}
}
