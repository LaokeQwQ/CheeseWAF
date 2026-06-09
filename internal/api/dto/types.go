package dto

type Response struct {
	Data  any       `json:"data,omitempty"`
	Meta  any       `json:"meta,omitempty"`
	Error *APIError `json:"error,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type LoginRequest struct {
	Username string          `json:"username"`
	Password string          `json:"password"`
	TOTPCode string          `json:"totp_code"`
	CAPTCHA  *CAPTCHAPayload `json:"captcha,omitempty"`
}

type CAPTCHAPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

type SetupRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	AdminListen   string `json:"admin_listen"`
	AdminStrategy string `json:"admin_strategy"`
	AdminPublic   bool   `json:"admin_public"`
}
