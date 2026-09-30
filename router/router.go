package router

import (
	"plnmobile-cyber-guard/config"
	"plnmobile-cyber-guard/controller"
	"plnmobile-cyber-guard/middleware"
	"plnmobile-cyber-guard/model"

	"github.com/gofiber/fiber/v2"
)

func InitRoutes(app *fiber.App, ctl *controller.CyberGuardController, cfg *config.Config) {
	api := app.Group("/api/v1/cyber-guard")

	// -------------------------------------------------------------------------
	// MODUL 1: Security PIN Pattern Validation
	// Implementasi: Diproteksi oleh middleware.PINSecurityGuard
	// -------------------------------------------------------------------------
	api.Post(
		"/security/pin/validate",
		middleware.PINSecurityGuard(cfg.SecurityBlockBirthdate),
		ctl.ValidatePINHandler,
	)

	// -------------------------------------------------------------------------
	// MODUL 2: Duplicate Parameter Guard (HPP / Header / Body Collision)
	// Implementasi: Diproteksi oleh middleware.DuplicateParamGuard
	// -------------------------------------------------------------------------
	api.All(
		"/security/params/check-duplicates",
		middleware.DuplicateParamGuard(),
		ctl.CheckDuplicateParamsHandler,
	)

	// -------------------------------------------------------------------------
	// MODUL 3: Anomaly Parameter Guard (Unknown Params & Header Whitelist/Blocklist)
	// Implementasi: Diproteksi oleh middleware.AnomalyParamGuard
	// Model acuan: model.PaymentOrderRequest (order_id, amount, customer_id, payment_type)
	// -------------------------------------------------------------------------
	api.All(
		"/security/params/check-anomalies",
		middleware.AnomalyParamGuard(middleware.AnomalyGuardConfig{
			RequestModel:         model.PaymentOrderRequest{},
			HeaderBlocklist:      cfg.HeaderBlocklist,
			HeaderWhitelist:      cfg.HeaderWhitelist,
			EnforceStrictHeaders: false, // Set true jika ingin tolak semua custom header di luar whitelist
		}),
		ctl.CheckAnomalyParamsHandler,
	)
}
