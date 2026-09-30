package validator_test

import (
	"testing"

	"plnmobile-cyber-guard/pkg/validator"
)

func TestPINValidator(t *testing.T) {
	v := validator.NewPINValidator(false)

	tests := []struct {
		pin      string
		expected bool
		desc     string
	}{
		// 5 Pola Utama dari User
		{"123456", false, "Urutan angka naik"},
		{"654321", false, "Urutan angka turun"},
		{"111222", false, "Blok kembar 3 digit"},
		{"112233", false, "3 pasang angka kembar"},
		{"000000", false, "Angka kembar semua"},

		// Pola-pola variasi tambahan
		{"111111", false, "Angka kembar 1 semua"},
		{"999999", false, "Angka kembar 9 semua"},
		{"234567", false, "Urutan naik mulai 2"},
		{"987654", false, "Urutan turun mulai 9"},
		{"222333", false, "Triple pairs 222333"},
		{"445566", false, "Double pairs 445566"},
		{"121212", false, "Pola selang-seling 12"},
		{"101010", false, "Pola selang-seling 10"},
		{"123123", false, "Pengulangan 3 digit"},
		{"123321", false, "Pola cermin / palindrom"},
		{"147258", false, "Keypad walk vertikal"},
		{"258014", false, "Keypad pattern"},

		// Format salah
		{"12345", false, "Kurang dari 6 digit"},
		{"1234567", false, "Lebih dari 6 digit"},
		{"12345a", false, "Mengandung non-numerik"},

		// Contoh PIN Kuat / Valid
		{"947215", true, "PIN acak kuat 1"},
		{"839174", true, "PIN acak kuat 2"},
		{"714926", true, "PIN acak kuat 3"},
		{"582941", true, "PIN acak kuat 4"},
	}

	for _, tt := range tests {
		t.Run(tt.pin+"_"+tt.desc, func(t *testing.T) {
			res := v.Validate(tt.pin)
			if res.IsValid != tt.expected {
				t.Errorf("PIN %s (%s) expected valid=%v, got valid=%v, errors=%v",
					tt.pin, tt.desc, tt.expected, res.IsValid, res.Errors)
			}
		})
	}
}
