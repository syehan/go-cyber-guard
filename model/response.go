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
