package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"plnmobile-cyber-guard/middleware"
	"plnmobile-cyber-guard/model"

	"github.com/gofiber/fiber/v2"
)

func setupAnomalyTestApp() *fiber.App {
	app := fiber.New()
	app.All(
		"/test-anomaly",
		middleware.AnomalyParamGuard(middleware.AnomalyGuardConfig{
			RequestModel: model.PaymentOrderRequest{}, // order_id, amount, customer_id, payment_type
			HeaderBlocklist: []string{
				"x-forwarded-host",
				"x-original-url",
				"x-admin-override",
			},
			HeaderWhitelist: []string{
				"content-type",
				"authorization",
				"x-signature",
			},
			EnforceStrictHeaders: false,
		}),
		func(c *fiber.Ctx) error {
			return c.SendString("OK")
		},
	)
	return app
}

func TestAnomalyParamGuard_AllowedParams(t *testing.T) {
	app := setupAnomalyTestApp()

	// 1. Valid Query & Body
	body := []byte(`{"order_id": "ORD-1", "amount": 50000}`)
	req := httptest.NewRequest("POST", "/test-anomaly?customer_id=CUST-1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for valid parameters, got %d", resp.StatusCode)
	}
}

func TestAnomalyParamGuard_UnknownQueryParam(t *testing.T) {
	app := setupAnomalyTestApp()

	// 2. Unknown Query Param (?hacker_param=123)
	req := httptest.NewRequest("GET", "/test-anomaly?hacker_param=123", nil)
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for unknown query parameter, got %d", resp.StatusCode)
	}
}

func TestAnomalyParamGuard_UnknownBodyParam(t *testing.T) {
	app := setupAnomalyTestApp()

	// 3. Unknown Body Param ({"is_admin": true})
	body := []byte(`{"order_id": "ORD-1", "is_admin": true}`)
	req := httptest.NewRequest("POST", "/test-anomaly", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for unknown body parameter, got %d", resp.StatusCode)
	}
}

func TestAnomalyParamGuard_BlocklistedHeader(t *testing.T) {
	app := setupAnomalyTestApp()

	// 4. Blocklisted Header (X-Admin-Override)
	req := httptest.NewRequest("GET", "/test-anomaly", nil)
	req.Header.Set("X-Admin-Override", "true")
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for blocklisted header, got %d", resp.StatusCode)
	}
}
