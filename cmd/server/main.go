package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
	"github.com/ingvarch/gitlab-slack-webhook/internal/logger"
	"github.com/ingvarch/gitlab-slack-webhook/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Application error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Initialize configuration
	cfg, err := config.SetupConfig(ctx)
	if err != nil {
		return fmt.Errorf("setup config: %w", err)
	}

	// Initialize custom logger
	logger.InitLogger(cfg)

	app := server.NewServer(cfg)
	go func() {
		if err := app.Listen(":" + cfg.Port); err != nil {
			slog.Error("Server error", "error", err)
			cancel()
		}
	}()

	slog.Info("Server started", "port", cfg.Port)

	<-ctx.Done()
	slog.Info("Shutting down gracefully")

	if err := app.Shutdown(); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}

	return nil
}
