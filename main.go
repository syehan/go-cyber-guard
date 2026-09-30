package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"plnmobile-cyber-guard/config"
	"plnmobile-cyber-guard/controller"
	"plnmobile-cyber-guard/router"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	// 1. Load config via Viper
	cfg := config.LoadConfig("./")

	log.Printf("Starting %s v%s on port :%s [ENV: %s]...", cfg.AppName, cfg.AppVersion, cfg.AppPort, cfg.AppEnv)

	// 2. Init Fiber app
	app := fiber.New(fiber.Config{
		AppName:      cfg.AppName,
		ServerHeader: "PLNMobile-Cyber-Guard",
	})

	// 3. Middlewares
	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, OPTIONS",
	}))
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path}\n",
	}))

	// Health Check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "UP",
			"app":     cfg.AppName,
			"version": cfg.AppVersion,
		})
	})

	// 4. Init Controller & Routes
	cyberGuardCtl := controller.NewCyberGuardController(cfg)
	router.InitRoutes(app, cyberGuardCtl)

	// 5. Graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Gracefully shutting down Cyber Guard service...")
		_ = app.ShutdownWithContext(context.Background())
	}()

	// 6. Start server
	addr := fmt.Sprintf(":%s", cfg.AppPort)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("Server stopped with error: %v", err)
	}

	log.Println("Server exited properly.")
}
