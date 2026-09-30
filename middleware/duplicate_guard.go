package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"plnmobile-cyber-guard/model"

	"github.com/gofiber/fiber/v2"
)

// DuplicateGuardConfig opsi konfigurasi untuk middleware DuplicateParamGuard
type DuplicateGuardConfig struct {
	CheckURLQuery bool
	CheckHeaders  bool
	CheckBody     bool
}

var DefaultDuplicateGuardConfig = DuplicateGuardConfig{
	CheckURLQuery: true,
	CheckHeaders:  true,
	CheckBody:     true,
}

// DuplicateParamGuard mencegah serangan HTTP Parameter Pollution (HPP)
// baik di URL Query (?a=1&a=2), Headers (Duplikat nama header), maupun JSON Body ("key": 1, "key": 2)
func DuplicateParamGuard(config ...DuplicateGuardConfig) fiber.Handler {
	cfg := DefaultDuplicateGuardConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx) error {
		var detectedViolations []model.ViolationDetail

		// 1. Cek Duplikasi di URL Query String
		if cfg.CheckURLQuery {
			rawQuery := string(c.Request().URI().QueryString())
			if rawQuery != "" {
				dupQueryParams := detectDuplicateQuery(rawQuery)
				for _, param := range dupQueryParams {
					detectedViolations = append(detectedViolations, model.ViolationDetail{
						Code:    "ERR_DUPLICATE_QUERY_PARAM",
						Rule:    "URL Query Parameter Duplication (HPP Attack)",
						Message: fmt.Sprintf("Terdeteksi duplikasi parameter query pada URL: '%s'", param),
					})
				}
			}
		}

		// 2. Cek Duplikasi di HTTP Headers
		if cfg.CheckHeaders {
			rawHeaders := string(c.Request().Header.Header())
			dupHeaders := detectDuplicateHeaders(rawHeaders)
			for _, h := range dupHeaders {
				detectedViolations = append(detectedViolations, model.ViolationDetail{
					Code:    "ERR_DUPLICATE_HEADER",
					Rule:    "HTTP Header Duplication (Header Smuggling / HPP)",
					Message: fmt.Sprintf("Terdeteksi duplikasi nama HTTP header: '%s'", h),
				})
			}
		}

		// 3. Cek Duplikasi Key di JSON / Form Body
		if cfg.CheckBody && len(c.Body()) > 0 {
			contentType := string(c.Request().Header.ContentType())

			if strings.Contains(contentType, "application/json") {
				dupJSONKeys, err := detectDuplicateJSONKeys(c.Body())
				if err == nil {
					for _, k := range dupJSONKeys {
						detectedViolations = append(detectedViolations, model.ViolationDetail{
							Code:    "ERR_DUPLICATE_BODY_KEY",
							Rule:    "JSON Body Duplicate Key Collision",
							Message: fmt.Sprintf("Terdeteksi duplikasi key pada JSON request body: '%s'", k),
						})
					}
				}
			} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
				rawBody := string(c.Body())
				dupFormParams := detectDuplicateQuery(rawBody)
				for _, p := range dupFormParams {
					detectedViolations = append(detectedViolations, model.ViolationDetail{
						Code:    "ERR_DUPLICATE_FORM_PARAM",
						Rule:    "Form Body Duplicate Parameter",
						Message: fmt.Sprintf("Terdeteksi duplikasi parameter pada form body: '%s'", p),
					})
				}
			}
		}

		// Jika ditemukan duplikasi, langsung blok request dengan 400 Bad Request
		if len(detectedViolations) > 0 {
			return c.Status(http.StatusBadRequest).JSON(model.BaseResponse{
				ResponseCode: "01",
				Message:      "Request ditolak oleh Cyber Mobile Guard: Terdeteksi duplikasi parameter/header (Parameter Pollution)",
				Data: fiber.Map{
					"total_violations": len(detectedViolations),
					"violations":       detectedViolations,
				},
			})
		}

		return c.Next()
	}
}

// Helper untuk deteksi duplikat query string (misal: "foo=1&bar=2&foo=3")
func detectDuplicateQuery(queryString string) []string {
	seen := make(map[string]bool)
	duplicates := make(map[string]bool)

	parts := strings.Split(queryString, "&")
	for _, part := range parts {
		if part == "" {
			continue
		}
		pair := strings.SplitN(part, "=", 2)
		rawKey := pair[0]
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}

		// Case-insensitive check untuk parameter query
		normalized := strings.ToLower(strings.TrimSpace(key))
		if seen[normalized] {
			duplicates[key] = true
		} else {
			seen[normalized] = true
		}
	}

	result := make([]string, 0, len(duplicates))
	for k := range duplicates {
		result = append(result, k)
	}
	return result
}

// Helper untuk deteksi duplikasi Header
func detectDuplicateHeaders(rawHeader string) []string {
	seen := make(map[string]bool)
	duplicates := make(map[string]bool)

	// Format raw header: Key: Value\r\n
	lines := strings.Split(rawHeader, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			headerName := strings.TrimSpace(line[:colonIdx])
			normalized := strings.ToLower(headerName)

			// Abaikan header yang secara RFC boleh multiple comma-separated seperti Accept/Cookie/Set-Cookie
			if normalized == "cookie" || normalized == "accept" || normalized == "accept-encoding" {
				continue
			}

			if seen[normalized] {
				duplicates[headerName] = true
			} else {
				seen[normalized] = true
			}
		}
	}

	result := make([]string, 0, len(duplicates))
	for k := range duplicates {
		result = append(result, k)
	}
	return result
}

// Helper mendeteksi duplikat key dalam JSON menggunakan json.Decoder
func detectDuplicateJSONKeys(bodyBytes []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	duplicates := make(map[string]bool)

	err := scanJSONKeys(dec, duplicates)
	if err != nil && err != io.EOF {
		return nil, err
	}

	result := make([]string, 0, len(duplicates))
	for k := range duplicates {
		result = append(result, k)
	}
	return result, nil
}

func scanJSONKeys(dec *json.Decoder, duplicates map[string]bool) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seenInThisObject := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key := keyTok.(string)
			normalizedKey := strings.ToLower(key)

			if seenInThisObject[normalizedKey] {
				duplicates[key] = true
			} else {
				seenInThisObject[normalizedKey] = true
			}

			// Rekursif ke value (jika nested object atau array)
			if err := scanJSONKeys(dec, duplicates); err != nil {
				return err
			}
		}
		// Baca closing '}'
		_, _ = dec.Token()

	case '[':
		for dec.More() {
			if err := scanJSONKeys(dec, duplicates); err != nil {
				return err
			}
		}
		// Baca closing ']'
		_, _ = dec.Token()
	}

	return nil
}
