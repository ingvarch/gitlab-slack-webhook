package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
)

func NewServer(_ *config.Config) *fiber.App {
	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("GitLab-Slack Webhook Server is running!")
	})

	return app
}
