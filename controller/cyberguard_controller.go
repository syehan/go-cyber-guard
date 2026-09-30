package controller

import (
	"net/http"

	"plnmobile-cyber-guard/config"
	"plnmobile-cyber-guard/model"

	"github.com/gofiber/fiber/v2"
)

type CyberGuardController struct {
	cfg *config.Config
}

func NewCyberGuardController(cfg *config.Config) *CyberGuardController {
	return &CyberGuardController{
		cfg: cfg,
	}
}

// 1. Controller untuk Modul Validasi Pola PIN
// Validasi logic ditangani langsung oleh middleware.PINSecurityGuard
func (ctl *CyberGuardController) ValidatePINHandler(c *fiber.Ctx) error {
	pin, _ := c.Locals("validated_pin").(string)

	return c.Status(http.StatusOK).JSON(model.BaseResponse{
		ResponseCode: "00",
		Message:      "PIN valid dan memenuhi standar keamanan Cyber Mobile",
		Data: model.PINValidationResponse{
			PIN:         pin,
			IsValid:     true,
			TotalIssues: 0,
		},
	})
}

// 2. Controller Dummy untuk Modul Pengujian Duplicate Parameter Guard
// Validasi logic ditangani langsung oleh middleware.DuplicateParamGuard
func (ctl *CyberGuardController) CheckDuplicateParamsHandler(c *fiber.Ctx) error {
	return c.Status(http.StatusOK).JSON(model.BaseResponse{
		ResponseCode: "00",
		Message:      "Request aman: Tidak ditemukan duplikasi parameter pada URL Query, Headers, maupun Body",
		Data: fiber.Map{
			"url_query": string(c.Request().URI().QueryString()),
			"method":    c.Method(),
			"body":      string(c.Body()),
		},
	})
}

// 3. Controller Dummy untuk Modul Pengujian Anomaly Parameter Guard
// Validasi logic ditangani langsung oleh middleware.AnomalyParamGuard
func (ctl *CyberGuardController) CheckAnomalyParamsHandler(c *fiber.Ctx) error {
	return c.Status(http.StatusOK).JSON(model.BaseResponse{
		ResponseCode: "00",
		Message:      "Request lolos validasi anomali: Semua URL Query, Body, dan Header sesuai spesifikasi model",
		Data: fiber.Map{
			"url_query": string(c.Request().URI().QueryString()),
			"body":      string(c.Body()),
		},
	})
}
