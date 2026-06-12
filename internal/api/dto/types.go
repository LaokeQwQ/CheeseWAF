package dto

type Response struct {
	Data  any       `json:"data,omitempty"`
	Meta  any       `json:"meta,omitempty"`
	Error *APIError `json:"error,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	TraceID string `json:"trace_id,omitempty"`
}

type LoginRequest struct {
	Username string          `json:"username"`
	Password string          `json:"password"`
	TOTPCode string          `json:"totp_code"`
	CAPTCHA  *CAPTCHAPayload `json:"captcha,omitempty"`
}

type CAPTCHAChallengeRequest struct {
	Mode string `json:"mode,omitempty"`
}

type CAPTCHAPayload struct {
	Mode      string                `json:"mode,omitempty"`
	Receipt   string                `json:"receipt,omitempty"`
	Algorithm string                `json:"algorithm"`
	Challenge string                `json:"challenge"`
	Number    int                   `json:"number"`
	Salt      string                `json:"salt"`
	Signature string                `json:"signature"`
	Slider    *SliderCAPTCHAPayload `json:"slider,omitempty"`
}

type SliderCAPTCHAPayload struct {
	Token  string `json:"token"`
	X      int    `json:"x"`
	DragMS int    `json:"drag_ms"`
}

type SetupRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	AdminListen   string `json:"admin_listen"`
	AdminStrategy string `json:"admin_strategy"`
	AdminPublic   bool   `json:"admin_public"`
}
