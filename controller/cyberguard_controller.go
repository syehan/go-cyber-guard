package controller

import (
	"net/http"
	"strings"

	"plnmobile-cyber-guard/config"
	"plnmobile-cyber-guard/model"
	"plnmobile-cyber-guard/pkg/validator"

	"github.com/gofiber/fiber/v2"
)

type CyberGuardController struct {
	cfg       *config.Config
	validator *validator.PINValidator
}

func NewCyberGuardController(cfg *config.Config) *CyberGuardController {
	return &CyberGuardController{
		cfg:       cfg,
		validator: validator.NewPINValidator(cfg.SecurityBlockBirthdate),
	}
}

// ValidatePIN - 1 API terpadu untuk modul validasi keamanan Pola PIN
func (ctl *CyberGuardController) ValidatePIN(c *fiber.Ctx) error {
	req := new(model.ValidatePINRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(model.BaseResponse{
			ResponseCode: "01",
			Message:      "Format request body tidak valid (harus JSON)",
			Errors:       err.Error(),
		})
	}

	pin := strings.TrimSpace(req.PIN)
	if pin == "" {
		return c.Status(http.StatusBadRequest).JSON(model.BaseResponse{
			ResponseCode: "01",
			Message:      "Parameter 'pin' wajib diisi",
			Errors:       "pin cannot be empty",
		})
	}

	var violations []model.ViolationDetail

	if !validator.IsNumeric6Digits(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_FORMAT_LENGTH",
			Rule:    "Panjang dan Tipe Data",
			Message: "PIN harus berupa tepat 6 digit angka numerik",
		})
	}

	if validator.IsRepeated(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_REPEATED_DIGITS",
			Rule:    "Angka Kembar Semua (contoh: 000000, 111111)",
			Message: validator.ErrRepeatedDigits.Error(),
		})
	}

	if validator.IsSequentialAscending(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_SEQUENTIAL_ASC",
			Rule:    "Urutan Angka Naik (contoh: 123456, 234567)",
			Message: validator.ErrSequentialAsc.Error(),
		})
	}

	if validator.IsSequentialDescending(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_SEQUENTIAL_DESC",
			Rule:    "Urutan Angka Turun (contoh: 654321, 543210)",
			Message: validator.ErrSequentialDesc.Error(),
		})
	}

	if validator.IsTriplePairs(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_TRIPLE_PAIRS",
			Rule:    "Blok Kembar 3 Digit (contoh: 111222, 999000)",
			Message: validator.ErrTriplePairs.Error(),
		})
	}

	if validator.IsDoublePairs(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_DOUBLE_PAIRS",
			Rule:    "3 Pasang Angka Kembar (contoh: 112233, 445566)",
			Message: validator.ErrDoublePairs.Error(),
		})
	}

	if validator.IsAlternating(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_ALTERNATING",
			Rule:    "Pola Selang-Seling (contoh: 121212, 101010)",
			Message: validator.ErrAlternating.Error(),
		})
	}

	if validator.IsRepeatedTriple(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_REPEATED_TRIPLE",
			Rule:    "Pengulangan 3 Digit Blok Pertama (contoh: 123123)",
			Message: validator.ErrRepeatedTriple.Error(),
		})
	}

	if validator.IsMirror(pin) && !validator.IsRepeated(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_MIRROR_PALINDROME",
			Rule:    "Pola Cermin / Palindrom (contoh: 123321)",
			Message: validator.ErrMirrorPattern.Error(),
		})
	}

	if validator.IsKeypadStraight(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_KEYPAD_STRAIGHT",
			Rule:    "Pola Garis Lurus Keypad HP/ATM (contoh: 147258, 258014)",
			Message: validator.ErrKeyboardWalk.Error(),
		})
	}

	if validator.IsCommonWeakPIN(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_COMMON_WEAK_PIN",
			Rule:    "Daftar PIN Sangat Populer / Mudah Ditebak",
			Message: validator.ErrCommonWeakPIN.Error(),
		})
	}

	if ctl.cfg.SecurityBlockBirthdate && validator.IsPossibleDate(pin) {
		violations = append(violations, model.ViolationDetail{
			Code:    "ERR_DATE_PATTERN",
			Rule:    "Pola Tanggal / Tahun Lahir Valid (DDMMYY/MMDDYY/YYMMDD)",
			Message: validator.ErrDatePattern.Error(),
		})
	}

	isValid := len(violations) == 0

	if !isValid {
		return c.Status(http.StatusUnprocessableEntity).JSON(model.BaseResponse{
			ResponseCode: "01",
			Message:      "PIN ditolak karena mengandung pola lemah atau dilarang",
			Data: model.PINValidationResponse{
				PIN:         pin,
				IsValid:     false,
				TotalIssues: len(violations),
				Violations:  violations,
			},
		})
	}

	return c.Status(http.StatusOK).JSON(model.BaseResponse{
		ResponseCode: "00",
		Message:      "PIN valid dan memenuhi standar keamanan PLN Mobile",
		Data: model.PINValidationResponse{
			PIN:         pin,
			IsValid:     true,
			TotalIssues: 0,
		},
	})
}
