package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"plnmobile-cyber-guard/middleware"

	"github.com/gofiber/fiber/v2"
)

func setupTestApp() *fiber.App {
	app := fiber.New()
	app.All("/test-duplicate", middleware.DuplicateParamGuard(), func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	app.Post("/test-pin", middleware.PINSecurityGuard(true), func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	return app
}

func TestDuplicateParamGuard_URLQuery(t *testing.T) {
	app := setupTestApp()

	// 1. Normal Query (No duplicate)
	req := httptest.NewRequest("GET", "/test-duplicate?id=123&name=budi", nil)
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// 2. Duplicate Query (id=123&id=456)
	reqDup := httptest.NewRequest("GET", "/test-duplicate?id=123&id=456", nil)
	respDup, err := app.Test(reqDup)
	if err != nil || respDup.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for duplicate query, got %d", respDup.StatusCode)
	}
}

func TestDuplicateParamGuard_JSONBody(t *testing.T) {
	app := setupTestApp()

	// 1. Normal JSON
	validJSON := []byte(`{"id": 123, "name": "test"}`)
	req := httptest.NewRequest("POST", "/test-duplicate", bytes.NewReader(validJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// 2. Duplicate JSON Key ("id": 1, "id": 2)
	dupJSON := []byte(`{"id": 1, "name": "budi", "id": 2}`)
	reqDup := httptest.NewRequest("POST", "/test-duplicate", bytes.NewReader(dupJSON))
	reqDup.Header.Set("Content-Type", "application/json")
	respDup, err := app.Test(reqDup)
	if err != nil || respDup.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for duplicate JSON keys, got %d", respDup.StatusCode)
	}
}

func TestPINSecurityGuard_Middleware(t *testing.T) {
	app := setupTestApp()

	// 1. Weak PIN: 123456
	weakBody := []byte(`{"pin": "123456"}`)
	req := httptest.NewRequest("POST", "/test-pin", bytes.NewReader(weakBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil || resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("Expected 422 for weak pin, got %d", resp.StatusCode)
	}

	// 2. Strong PIN: 947215
	strongBody := []byte(`{"pin": "947215"}`)
	reqStrong := httptest.NewRequest("POST", "/test-pin", bytes.NewReader(strongBody))
	reqStrong.Header.Set("Content-Type", "application/json")
	respStrong, err := app.Test(reqStrong)
	if err != nil || respStrong.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for strong pin, got %d", respStrong.StatusCode)
	}
}
