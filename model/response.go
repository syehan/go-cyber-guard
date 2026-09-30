package model

type BaseResponse struct {
	ResponseCode string `json:"response_code"`
	Message      string `json:"message"`
	Data         any    `json:"data,omitempty"`
	Errors       any    `json:"errors,omitempty"`
}

type ValidatePINRequest struct {
	PIN string `json:"pin"`
}

type ViolationDetail struct {
	Code    string `json:"code"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type PINValidationResponse struct {
	PIN         string            `json:"pin"`
	IsValid     bool              `json:"is_valid"`
	TotalIssues int               `json:"total_issues"`
	Violations  []ViolationDetail `json:"violations,omitempty"`
}

// Dummy Model Request untuk pengujian Anomali Parameters
type PaymentOrderRequest struct {
	OrderID     string  `json:"order_id" query:"order_id" form:"order_id"`
	Amount      float64 `json:"amount" query:"amount" form:"amount"`
	CustomerID  string  `json:"customer_id" query:"customer_id" form:"customer_id"`
	PaymentType string  `json:"payment_type" query:"payment_type" form:"payment_type"`
}
