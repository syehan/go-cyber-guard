# Cyber Mobile Guard

Service keamanan backend berbasis **Golang** yang mengadopsi standar arsitektur microservices modern (Fiber v2, Viper configuration, graceful shutdown) yang bertugas memvalidasi berbagai lapisan keamanan input data dan request API.

Semua validasi keamanan di project ini dirancang sebagai **Middleware Fiber siap pakai (`middleware.*`)**, sehingga developer tinggal memasangnya di route endpoint masing-masing.

---

## 🛡️ Daftar Modul Validasi Keamanan (Middleware)

Berikut adalah modul-modul middleware keamanan yang telah aktif pada project ini:

---

### 1. Modul Validasi Pola PIN (`middleware.PINSecurityGuard`)
* **Fungsi:** Memvalidasi PIN 6-digit dari berbagai pola rentan/lemah yang umum digunakan oleh user dan rentan terhadap serangan brute force / dictionary attack.
* **Penggunaan oleh Developer:**
  ```go
  app.Post("/api/v1/auth/setup-pin", middleware.PINSecurityGuard(true), myController.SetupPIN)
  ```
* **Endpoint Uji Coba Dummy:** `POST /api/v1/cyber-guard/security/pin/validate`
* **Daftar Pola Terlarang:**

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

### 2. Modul Pengecekan Duplicate Parameters (`middleware.DuplicateParamGuard`)
* **Fungsi:** Mencegah serangan **HTTP Parameter Pollution (HPP)** dan **JSON / Header Smuggling** akibat duplikasi parameter nama yang sama.
* **Cakupan Proteksi:**
  1. **URL Query String:** Menolak request jika ada duplikasi parameter query (contoh: `?account_id=123&account_id=456`).
  2. **HTTP Headers:** Menolak request jika ada duplikasi nama header kustom.
  3. **Request Body (JSON & Form):** Menolak JSON payload yang memiliki duplicate keys pada level objek yang sama (contoh: `{"amount": 1000, "amount": 50000}`).
* **Penggunaan oleh Developer:**
  ```go
  // Pasang global untuk seluruh route
  app.Use(middleware.DuplicateParamGuard())

  // Atau pasang di route spesifik
  app.Post("/api/v1/payment/checkout", middleware.DuplicateParamGuard(), myController.Checkout)
  ```
* **Endpoint Uji Coba Dummy:** `POST /api/v1/cyber-guard/security/params/check-duplicates`
* **Daftar Kode Pelanggaran:**

| Kode Pelanggaran | Target | Contoh Skenario Serangan / Kesalahan |
|---|---|---|
| `ERR_DUPLICATE_QUERY_PARAM` | URL Query | `?user_id=10&role=user&user_id=20` |
| `ERR_DUPLICATE_HEADER` | HTTP Headers | Header ganda: `X-User-Role: user` dan `X-User-Role: admin` |
| `ERR_DUPLICATE_BODY_KEY` | JSON Body | `{"target": "accA", "target": "accB"}` |
| `ERR_DUPLICATE_FORM_PARAM` | Form URL-Encoded | `param=val1&param=val2` |

---

### 3. Modul Pengecekan Anomali Parameters (`middleware.AnomalyParamGuard`)
* **Fungsi:** Mendeteksi parameter siluman / tidak dikenal (*unknown parameters*) baik di URL Query maupun JSON Body, serta memvalidasi Header HTTP terhadap **Whitelist** dan **Blocklist** yang dikonfigurasi melalui `.env`.
* **Cakupan Proteksi:**
  1. **URL Query & Body Anomaly:** Secara otomatis membaca tag struct model (tag `json`, `query`, `form`) yang didefinisikan oleh developer. Jika client mengirim parameter yang tidak terdaftar di struct model (misal `is_admin=true`, `role=superuser`), request akan langsung **ditolak**.
  2. **Header Blocklist (.env):** Memblokir request yang mengandung header berbahaya/dilarang seperti `X-Forwarded-Host`, `X-Rewrite-URL`, `X-Original-URL`, `X-Admin-Override`.
  3. **Header Whitelist (.env):** Membatasi daftar custom header yang diizinkan selain standard HTTP headers.
* **Konfigurasi `.env`:**
  ```env
  SECURITY_HEADER_BLOCKLIST="x-forwarded-host,x-original-url,x-rewrite-url,x-admin-override,x-debug-mode,x-http-method-override"
  SECURITY_HEADER_WHITELIST="content-type,authorization,accept,x-app-version,x-platform,x-request-id,x-signature,x-timestamp"
  ```
* **Penggunaan oleh Developer:**
  ```go
  // Cukup masukkan struct model request Anda ke konfigurasi middleware
  app.Post("/api/v1/payment/charge",
      middleware.AnomalyParamGuard(middleware.AnomalyGuardConfig{
          RequestModel:    model.PaymentOrderRequest{}, // Hanya field order_id, amount, customer_id, payment_type
          HeaderBlocklist: cfg.HeaderBlocklist,
          HeaderWhitelist: cfg.HeaderWhitelist,
      }),
      myController.ChargePayment,
  )
  ```
* **Endpoint Uji Coba Dummy:** `ALL /api/v1/cyber-guard/security/params/check-anomalies`
  *(Model acuan pengujian: `order_id`, `amount`, `customer_id`, `payment_type`)*
* **Daftar Kode Pelanggaran:**

| Kode Pelanggaran | Target | Contoh Skenario Pelanggaran |
|---|---|---|
| `ERR_ANOMALY_QUERY_PARAM` | URL Query | `?order_id=123&is_admin=true` (`is_admin` tidak ada di model) |
| `ERR_ANOMALY_BODY_PARAM` | JSON Body | `{"order_id": "1", "role": "admin"}` (`role` tidak ada di model) |
| `ERR_ANOMALY_HEADER_BLOCKLISTED` | HTTP Headers | Mengirim header `X-Admin-Override: true` atau `X-Original-URL` |
| `ERR_ANOMALY_HEADER_NOT_WHITELISTED` | HTTP Headers | Mengirim custom header asing yang tidak terdaftar di whitelist |

---

## 🚀 Menjalankan Service

### 1. Menjalankan Unit Test
```bash
go test -v ./...
```

### 2. Menjalankan Server
```bash
go run cmd/main.go
```
*Server berjalan pada port `8085` (dapat dikonfigurasi melalui file `.env`).*

---

## 📮 Koleksi Postman & Panduan Pengujian

File koleksi Postman siap pakai: `postman_collection.json`

### 1. Uji Validasi PIN
- **URL:** `POST http://localhost:8085/api/v1/cyber-guard/security/pin/validate`
- **Body:** `{"pin": "123456"}` -> Response HTTP `422 Unprocessable Entity`
- **Body:** `{"pin": "947215"}` -> Response HTTP `200 OK`

### 2. Uji Duplicate Parameters
- **URL:** `GET http://localhost:8085/api/v1/cyber-guard/security/params/check-duplicates?order_id=101&order_id=999` -> HTTP `400 Bad Request`
- **URL:** `POST http://localhost:8085/api/v1/cyber-guard/security/params/check-duplicates` dengan body `{"amount": 100, "amount": 200}` -> HTTP `400 Bad Request`

### 3. Uji Anomaly Parameters
- **URL:** `POST http://localhost:8085/api/v1/cyber-guard/security/params/check-anomalies?hacker_query=true` -> HTTP `400 Bad Request` (`ERR_ANOMALY_QUERY_PARAM`)
- **Body:** `{"order_id": "ORD-1", "unexpected_payload": "hack"}` -> HTTP `400 Bad Request` (`ERR_ANOMALY_BODY_PARAM`)
- **Header:** `X-Admin-Override: true` -> HTTP `400 Bad Request` (`ERR_ANOMALY_HEADER_BLOCKLISTED`)
- **Permintaan Sah:** Body `{"order_id": "ORD-1", "amount": 25000}` tanpa header terlarang -> HTTP `200 OK`
