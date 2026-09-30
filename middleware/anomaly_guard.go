package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"plnmobile-cyber-guard/model"

	"github.com/gofiber/fiber/v2"
)

// AnomalyGuardConfig konfigurasi untuk middleware AnomalyParamGuard
type AnomalyGuardConfig struct {
	// RequestModel contoh struct model yang diharapkan (e.g. model.CreateUserRequest{})
	// Digunakan untuk mengecek unknown/anomali parameter pada URL Query dan JSON Body
	RequestModel any

	// Header Whitelist & Blocklist (diambil dari .env)
	HeaderBlocklist []string
	HeaderWhitelist []string

	// EnforceStrictHeaders jika true, header non-standar yang tidak ada di whitelist akan diblok
	EnforceStrictHeaders bool
}

// Daftar Standard HTTP Headers yang selalu diizinkan agar komunikasi protokol normal tidak terganggu
var standardHTTPHeaders = map[string]bool{
	"host":               true,
	"user-agent":         true,
	"accept":             true,
	"accept-language":    true,
	"accept-encoding":    true,
	"content-type":       true,
	"content-length":     true,
	"authorization":      true,
	"connection":         true,
	"cache-control":      true,
	"pragma":             true,
	"cookie":             true,
	"origin":             true,
	"referer":            true,
	"sec-ch-ua":          true,
	"sec-ch-ua-mobile":   true,
	"sec-ch-ua-platform": true,
	"sec-fetch-dest":     true,
	"sec-fetch-mode":     true,
	"sec-fetch-site":     true,
	"upgrade-insecure-requests": true,
}

// AnomalyParamGuard mendeteksi anomali parameter:
// 1. Unknown / Anomali URL Query Parameters (berdasarkan tag form/query/json struct model)
// 2. Unknown / Anomali Body Keys (berdasarkan tag json struct model)
// 3. Blocklisted atau Non-Whitelisted Headers (berdasarkan konfigurasi .env)
func AnomalyParamGuard(cfg AnomalyGuardConfig) fiber.Handler {
	allowedParamsMap := extractAllowedParams(cfg.RequestModel)

	blocklistMap := make(map[string]bool)
	for _, h := range cfg.HeaderBlocklist {
		blocklistMap[strings.ToLower(strings.TrimSpace(h))] = true
	}

	whitelistMap := make(map[string]bool)
	for _, h := range cfg.HeaderWhitelist {
		whitelistMap[strings.ToLower(strings.TrimSpace(h))] = true
	}

	return func(c *fiber.Ctx) error {
		var detectedViolations []model.ViolationDetail

		// ---------------------------------------------------------------------
		// 1. Pengecekan Anomali Header (Blocklist & Whitelist)
		// ---------------------------------------------------------------------
		rawHeaders := string(c.Request().Header.Header())
		lines := strings.Split(rawHeaders, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				headerKey := strings.TrimSpace(line[:colonIdx])
				normalizedKey := strings.ToLower(headerKey)

				// A. Cek Header Blocklist
				if blocklistMap[normalizedKey] {
					detectedViolations = append(detectedViolations, model.ViolationDetail{
						Code:    "ERR_ANOMALY_HEADER_BLOCKLISTED",
						Rule:    "Header Terlarang / Berbahaya (Blocklist)",
						Message: fmt.Sprintf("Header '%s' dilarang oleh kebijakan keamanan (.env blocklist)", headerKey),
					})
				}

				// B. Cek Header Whitelist (jika whitelist diisi dan header bukan standard HTTP)
				if cfg.EnforceStrictHeaders && len(whitelistMap) > 0 {
					if !standardHTTPHeaders[normalizedKey] && !whitelistMap[normalizedKey] {
						detectedViolations = append(detectedViolations, model.ViolationDetail{
							Code:    "ERR_ANOMALY_HEADER_NOT_WHITELISTED",
							Rule:    "Header Tidak Terdaftar (Whitelist)",
							Message: fmt.Sprintf("Header '%s' tidak terdaftar pada whitelist yang diizinkan (.env whitelist)", headerKey),
						})
					}
				}
			}
		}

		// ---------------------------------------------------------------------
		// 2. Pengecekan Anomali URL Query Parameters (Berdasarkan Model Request)
		// ---------------------------------------------------------------------
		rawQuery := string(c.Request().URI().QueryString())
		if rawQuery != "" && len(allowedParamsMap) > 0 {
			parts := strings.Split(rawQuery, "&")
			for _, part := range parts {
				if part == "" {
					continue
				}
				pair := strings.SplitN(part, "=", 2)
				key, _ := url.QueryUnescape(pair[0])
				normalizedKey := strings.ToLower(strings.TrimSpace(key))

				if !allowedParamsMap[normalizedKey] {
					detectedViolations = append(detectedViolations, model.ViolationDetail{
						Code:    "ERR_ANOMALY_QUERY_PARAM",
						Rule:    "Parameter Query Tidak Dikenal (Unknown Query Param)",
						Message: fmt.Sprintf("Parameter query '%s' tidak didefinisikan pada model request", key),
					})
				}
			}
		}

		// ---------------------------------------------------------------------
		// 3. Pengecekan Anomali JSON Body Parameters (Berdasarkan Model Request)
		// ---------------------------------------------------------------------
		if len(c.Body()) > 0 && len(allowedParamsMap) > 0 {
			contentType := string(c.Request().Header.ContentType())
			if strings.Contains(contentType, "application/json") {
				var bodyMap map[string]any
				if err := json.Unmarshal(c.Body(), &bodyMap); err == nil {
					for key := range bodyMap {
						normalizedKey := strings.ToLower(strings.TrimSpace(key))
						if !allowedParamsMap[normalizedKey] {
							detectedViolations = append(detectedViolations, model.ViolationDetail{
								Code:    "ERR_ANOMALY_BODY_PARAM",
								Rule:    "Parameter Body Tidak Dikenal (Unknown Body Param)",
								Message: fmt.Sprintf("Parameter body '%s' tidak didefinisikan pada model request", key),
							})
						}
					}
				}
			}
		}

		// Jika ada anomali yang ditemukan, tolak request
		if len(detectedViolations) > 0 {
			return c.Status(http.StatusBadRequest).JSON(model.BaseResponse{
				ResponseCode: "01",
				Message:      "Request ditolak oleh Cyber Mobile Guard: Terdeteksi anomali parameter atau header tidak sah",
				Data: fiber.Map{
					"total_violations": len(detectedViolations),
					"violations":       detectedViolations,
				},
			})
		}

		return c.Next()
	}
}

// extractAllowedParams mengekstrak nama field yang diizinkan dari struct tags (json, form, query)
func extractAllowedParams(modelInstance any) map[string]bool {
	allowed := make(map[string]bool)
	if modelInstance == nil {
		return allowed
	}

	val := reflect.ValueOf(modelInstance)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return allowed
	}

	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		// 1. Tag JSON
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			tagName := strings.Split(jsonTag, ",")[0]
			allowed[strings.ToLower(tagName)] = true
		}

		// 2. Tag Query
		queryTag := field.Tag.Get("query")
		if queryTag != "" && queryTag != "-" {
			tagName := strings.Split(queryTag, ",")[0]
			allowed[strings.ToLower(tagName)] = true
		}

		// 3. Tag Form
		formTag := field.Tag.Get("form")
		if formTag != "" && formTag != "-" {
			tagName := strings.Split(formTag, ",")[0]
			allowed[strings.ToLower(tagName)] = true
		}

		// 4. Default Field Name jika tag tidak ada
		allowed[strings.ToLower(field.Name)] = true
	}

	return allowed
}
