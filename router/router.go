package router

import (
	"plnmobile-cyber-guard/controller"

	"github.com/gofiber/fiber/v2"
)

func InitRoutes(app *fiber.App, ctl *controller.CyberGuardController) {
	api := app.Group("/api/v1/cyber-guard")

	// 1. Modul Validasi Keamanan Pola PIN (Single Consolidated API)
	api.Post("/security/pin/validate", ctl.ValidatePIN)

	// Route untuk modul-modul security selanjutnya akan didaftarkan di sini:
	// api.Post("/security/request/check-duplicated-params", ...)
	// api.Post("/security/request/check-unknown-params", ...)
}
