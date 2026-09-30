# PLN Mobile Cyber Guard

Service keamanan backend berbasis **Golang** yang mengadopsi standar arsitektur **PLN Mobile** (Fiber v2, Viper configuration, graceful shutdown) yang bertugas memvalidasi berbagai lapisan keamanan input data dan request API.

---

## 🛡️ Daftar Modul Validasi Keamanan

Berikut adalah modul-modul validasi keamanan yang telah aktif pada project ini:

### 1. Modul Validasi Pola PIN (`POST /api/v1/cyber-guard/security/pin/validate`)
Satu API terpadu yang memvalidasi PIN 6-digit dari berbagai pola rentan/lemah yang umum digunakan oleh user dan rentan terhadap serangan brute force / social engineering:

| Kode Pelanggaran | Aturan & Pola yang Dilarang | Contoh Pola Terlarang |
|---|---|---|
| `ERR_FORMAT_LENGTH` | Tepat 6 digit angka numerik | `12345`, `1234567`, `12345a` |
| `ERR_REPEATED_DIGITS` | Digit berulang kembar semua | `000000`, `111111`, `999999` |
| `ERR_SEQUENTIAL_ASC` | Urutan angka naik berurutan | `123456`, `234567`, `456789` |
| `ERR_SEQUENTIAL_DESC` | Urutan angka turun berurutan | `654321`, `543210`, `987654` |
| `ERR_TRIPLE_PAIRS` | Blok kembar 3 digit (AAABBB) | `111222`, `222333`, `999000` |
| `ERR_DOUBLE_PAIRS` | Tiga pasang kembar berurutan (AABBCC) | `112233`, `445566`, `889900` |
| `ERR_ALTERNATING` | Pola selang-seling (ABABAB) | `121212`, `101010`, `898989` |
| `ERR_REPEATED_TRIPLE` | Duplikasi 3 digit pertama (ABCABC) | `123123`, `456456`, `789789` |
| `ERR_MIRROR_PALINDROME` | Pola cermin / palindrom (ABCCBA) | `123321`, `258852`, `145541` |
| `ERR_KEYPAD_STRAIGHT` | Garis lurus keypad ATM / Layar HP | `147258`, `258014`, `369258`, `258147` |
| `ERR_COMMON_WEAK_PIN` | Daftar PIN paling populer / mudah ditebak | `123789`, `987123`, `135790`, `246802` |
| `ERR_DATE_PATTERN` | Tanggal lahir / tanggal valid (DDMMYY/MMDDYY/YYMMDD) | `170845`, `251290`, `010195` |

---

## 🚀 Menjalankan Service

### 1. Menjalankan Unit Test
```bash
go test -v ./...
```

### 2. Menjalankan Server
```bash
go run main.go
```
*Server akan mendengarkan pada port `8085` (dapat dikonfigurasi melalui file `.env`).*

---

## 📮 Dokumentasi API & Pengujian Postman

File konfigurasi Postman siap pakai tersedia di:
`postman_collection.json`

### Endpoint: Validasi Pola PIN
- **URL:** `http://localhost:8085/api/v1/cyber-guard/security/pin/validate`
- **Method:** `POST`
- **Header:** `Content-Type: application/json`

#### Contoh Request:
```json
{
  "pin": "123456"
}
```

#### Contoh Response (Gagal / Ditolak - HTTP 422):
```json
{
  "response_code": "01",
  "message": "PIN ditolak karena mengandung pola lemah atau dilarang",
  "data": {
    "pin": "123456",
    "is_valid": false,
    "total_issues": 3,
    "violations": [
      {
        "code": "ERR_SEQUENTIAL_ASC",
        "rule": "Urutan Angka Naik (contoh: 123456, 234567)",
        "message": "PIN tidak boleh berupa urutan angka naik berurutan (contoh: 123456, 234567)"
      },
      {
        "code": "ERR_KEYPAD_STRAIGHT",
        "rule": "Pola Garis Lurus Keypad HP/ATM (contoh: 147258, 258014)",
        "message": "PIN tidak boleh berupa pola garis lurus tombol keypad (contoh: 258014, 147258)"
      },
      {
        "code": "ERR_COMMON_WEAK_PIN",
        "rule": "Daftar PIN Sangat Populer / Mudah Ditebak",
        "message": "PIN termasuk daftar PIN sangat umum / mudah ditebak"
      }
    ]
  }
}
```

#### Contoh Response (Berhasil / Valid - HTTP 200):
```json
{
  "response_code": "00",
  "message": "PIN valid dan memenuhi standar keamanan PLN Mobile",
  "data": {
    "pin": "947215",
    "is_valid": true,
    "total_issues": 0
  }
}
```
