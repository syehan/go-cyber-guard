package validator

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var (
	ErrNotNumeric     = errors.New("PIN harus berupa angka numerik")
	ErrInvalidLength  = errors.New("PIN harus berjumlah tepat 6 digit")
	ErrRepeatedDigits = errors.New("PIN tidak boleh berisi digit yang sama berulang (contoh: 000000, 111111)")
	ErrSequentialAsc  = errors.New("PIN tidak boleh berupa urutan angka naik berurutan (contoh: 123456, 234567)")
	ErrSequentialDesc = errors.New("PIN tidak boleh berupa urutan angka turun berurutan (contoh: 654321, 987654)")
	ErrTriplePairs    = errors.New("PIN tidak boleh berupa blok kembar 3 digit (contoh: 111222, 999000)")
	ErrDoublePairs    = errors.New("PIN tidak boleh berupa 3 pasang angka kembar berurutan (contoh: 112233, 445566)")
	ErrAlternating    = errors.New("PIN tidak boleh berupa pola angka selang-seling (contoh: 121212, 101010)")
	ErrRepeatedTriple = errors.New("PIN tidak boleh mengulang 3 digit yang sama (contoh: 123123, 456456)")
	ErrMirrorPattern  = errors.New("PIN tidak boleh berupa pola cermin / palindrom (contoh: 123321, 258852)")
	ErrKeyboardWalk   = errors.New("PIN tidak boleh berupa pola garis lurus tombol keypad (contoh: 258014, 147258)")
	ErrCommonWeakPIN  = errors.New("PIN termasuk daftar PIN sangat umum / mudah ditebak")
	ErrDatePattern    = errors.New("PIN terdeteksi menyerupai pola tanggal valid / tahun lahir (DDMMYY / MMDDYY / YYYY)")
)

var numericRegex = regexp.MustCompile(`^\d{6}$`)

var commonWeakPINs = map[string]struct{}{
	"123456": {}, "654321": {}, "111111": {}, "000000": {}, "123123": {},
	"112233": {}, "121212": {}, "111222": {}, "666666": {}, "135790": {},
	"246802": {}, "012345": {}, "543210": {}, "987654": {}, "159753": {},
	"147258": {}, "258014": {}, "369258": {}, "987123": {}, "123789": {},
}

var keypadStraightPatterns = map[string]struct{}{
	"147258": {}, "258147": {}, "258369": {}, "369258": {}, "123456": {},
	"456789": {}, "789456": {}, "159357": {}, "357159": {}, "258025": {},
	"258014": {},
}

type PINValidationResult struct {
	PIN     string   `json:"pin"`
	IsValid bool     `json:"is_valid"`
	Errors  []string `json:"errors,omitempty"`
}

type PINValidator struct {
	blockDates bool
}

func NewPINValidator(blockDates bool) *PINValidator {
	return &PINValidator{blockDates: blockDates}
}

func (v *PINValidator) Validate(pin string) PINValidationResult {
	result := PINValidationResult{
		PIN:     pin,
		IsValid: true,
		Errors:  make([]string, 0),
	}

	if len(pin) != 6 {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrInvalidLength.Error())
		return result
	}

	if !numericRegex.MatchString(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrNotNumeric.Error())
		return result
	}

	if IsRepeated(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrRepeatedDigits.Error())
	}

	if IsSequentialAscending(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrSequentialAsc.Error())
	}

	if IsSequentialDescending(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrSequentialDesc.Error())
	}

	if IsTriplePairs(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrTriplePairs.Error())
	}

	if IsDoublePairs(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrDoublePairs.Error())
	}

	if IsAlternating(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrAlternating.Error())
	}

	if IsRepeatedTriple(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrRepeatedTriple.Error())
	}

	if IsMirror(pin) && !IsRepeated(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrMirrorPattern.Error())
	}

	if IsKeypadStraight(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrKeyboardWalk.Error())
	}

	if IsCommonWeakPIN(pin) {
		found := false
		for _, errStr := range result.Errors {
			if errStr == ErrCommonWeakPIN.Error() {
				found = true
				break
			}
		}
		if !found {
			result.IsValid = false
			result.Errors = append(result.Errors, ErrCommonWeakPIN.Error())
		}
	}

	if v.blockDates && IsPossibleDate(pin) {
		result.IsValid = false
		result.Errors = append(result.Errors, ErrDatePattern.Error())
	}

	return result
}

func IsNumeric6Digits(pin string) bool {
	return numericRegex.MatchString(pin)
}

func IsRepeated(pin string) bool {
	if len(pin) < 2 {
		return false
	}
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[0] {
			return false
		}
	}
	return true
}

func IsSequentialAscending(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	for i := 0; i < len(pin)-1; i++ {
		d1 := int(pin[i] - '0')
		d2 := int(pin[i+1] - '0')
		if (d1+1)%10 != d2 {
			return false
		}
	}
	return true
}

func IsSequentialDescending(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	for i := 0; i < len(pin)-1; i++ {
		d1 := int(pin[i] - '0')
		d2 := int(pin[i+1] - '0')
		if (d1+9)%10 != d2 {
			return false
		}
	}
	return true
}

func IsTriplePairs(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	firstPartSame := pin[0] == pin[1] && pin[1] == pin[2]
	secondPartSame := pin[3] == pin[4] && pin[4] == pin[5]
	return firstPartSame && secondPartSame
}

func IsDoublePairs(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	return pin[0] == pin[1] && pin[2] == pin[3] && pin[4] == pin[5]
}

func IsAlternating(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	return pin[0] == pin[2] && pin[2] == pin[4] &&
		pin[1] == pin[3] && pin[3] == pin[5] &&
		pin[0] != pin[1]
}

func IsRepeatedTriple(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	return pin[:3] == pin[3:]
}

func IsMirror(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	return pin[0] == pin[5] && pin[1] == pin[4] && pin[2] == pin[3]
}

func IsKeypadStraight(pin string) bool {
	_, ok := keypadStraightPatterns[pin]
	return ok
}

func IsCommonWeakPIN(pin string) bool {
	_, ok := commonWeakPINs[pin]
	return ok
}

func IsPossibleDate(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	day, _ := strconv.Atoi(pin[0:2])
	month, _ := strconv.Atoi(pin[2:4])
	year, _ := strconv.Atoi(pin[4:6])
	if isValidDate(day, month, year) {
		return true
	}

	month2, _ := strconv.Atoi(pin[0:2])
	day2, _ := strconv.Atoi(pin[2:4])
	if isValidDate(day2, month2, year) {
		return true
	}

	year3, _ := strconv.Atoi(pin[0:2])
	month3, _ := strconv.Atoi(pin[2:4])
	day3, _ := strconv.Atoi(pin[4:6])
	return isValidDate(day3, month3, year3)
}

func isValidDate(d, m, y int) bool {
	if m < 1 || m > 12 || d < 1 || d > 31 {
		return false
	}
	fullYear := 2000 + y
	if y > 50 {
		fullYear = 1900 + y
	}
	t := time.Date(fullYear, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	return t.Day() == d && int(t.Month()) == m
}

func FormatResult(res PINValidationResult) string {
	status := "VALID"
	if !res.IsValid {
		status = "REJECTED (Lemah/Pola Dilarang)"
	}
	out := fmt.Sprintf("[%s] PIN: %s", status, res.PIN)
	if len(res.Errors) > 0 {
		for _, e := range res.Errors {
			out += fmt.Sprintf("\n  - Alasan: %s", e)
		}
	}
	return out
}
