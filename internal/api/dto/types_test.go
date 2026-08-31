package dto

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// The dto package holds the console API wire contract. Every response the
// console serves is a Response envelope (internal/api/handler writeData /
// writeError, cluster.go, acme.go) and every login/setup request body is
// decoded into one of the request structs. The tests below pin that contract:
// field names, which fields are optional (omitempty) and which are always
// emitted, and how malformed payloads fail.

func marshalString(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%#v) returned error: %v", value, err)
	}
	return string(raw)
}

// unmarshalTypeErrorField reports the offending field when err is a
// *json.UnmarshalTypeError, so tests assert the failure shape and not just
// that an error happened.
func unmarshalTypeErrorField(err error) string {
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		return ""
	}
	return typeErr.Field
}

func TestResponseMarshalOmitempty(t *testing.T) {
	emptyMap := map[string]any{}
	emptySlice := []string{}
	var typedNil *int

	tests := []struct {
		name string
		resp Response
		want string
	}{
		{
			name: "zero value collapses to empty object",
			resp: Response{},
			want: `{}`,
		},
		{
			name: "data object",
			resp: Response{Data: map[string]any{"mode": "standalone"}},
			want: `{"data":{"mode":"standalone"}}`,
		},
		{
			name: "meta object",
			resp: Response{Meta: map[string]any{"page": float64(1)}},
			want: `{"meta":{"page":1}}`,
		},
		{
			name: "error object omits empty trace and event ids",
			resp: Response{Error: &APIError{Code: "BAD_REQUEST", Message: "nope"}},
			want: `{"error":{"code":"BAD_REQUEST","message":"nope"}}`,
		},
		{
			name: "error object carries trace and event ids",
			resp: Response{Error: &APIError{Code: "E", Message: "m", TraceID: "tid", EventID: "tid"}},
			want: `{"error":{"code":"E","message":"m","trace_id":"tid","event_id":"tid"}}`,
		},
		{
			name: "data and error coexist",
			resp: Response{Data: "partial", Error: &APIError{Code: "E", Message: "m"}},
			want: `{"data":"partial","error":{"code":"E","message":"m"}}`,
		},
		// Data is `any`, and omitempty only drops a nil *interface*. A
		// non-nil interface holding an empty value is still emitted, so
		// callers cannot rely on empty payloads being hidden.
		{
			name: "empty string data is still emitted",
			resp: Response{Data: ""},
			want: `{"data":""}`,
		},
		{
			name: "zero int data is still emitted",
			resp: Response{Data: 0},
			want: `{"data":0}`,
		},
		{
			name: "false bool data is still emitted",
			resp: Response{Data: false},
			want: `{"data":false}`,
		},
		{
			name: "empty map data is still emitted",
			resp: Response{Data: emptyMap},
			want: `{"data":{}}`,
		},
		{
			name: "empty slice data is still emitted",
			resp: Response{Data: emptySlice},
			want: `{"data":[]}`,
		},
		{
			name: "typed nil pointer data marshals as null",
			resp: Response{Data: typedNil},
			want: `{"data":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := marshalString(t, tt.resp)
			if got != tt.want {
				t.Fatalf("json.Marshal(Response) = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestResponseUnmarshalDataIntoGenericMap(t *testing.T) {
	// Handlers such as ClusterStatus decode straight into dto.Response and
	// type-assert Data to map[string]any, so nested JSON must survive as a
	// generic map and numbers must come back as float64.
	const body = `{"data":{"mode":"standalone","replicas":3,"nested":{"ok":true}},` +
		`"meta":{"page":1}}`
	var envelope Response
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("json.Unmarshal(Response) returned error: %v", err)
	}
	if envelope.Error != nil {
		t.Fatalf("Error = %#v, want nil", envelope.Error)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok {
		t.Fatalf("Data type = %T, want map[string]any", envelope.Data)
	}
	if data["mode"] != "standalone" {
		t.Fatalf("data[mode] = %#v, want standalone", data["mode"])
	}
	if data["replicas"] != float64(3) {
		t.Fatalf("data[replicas] = %#v (%T), want float64(3)", data["replicas"], data["replicas"])
	}
	nested, ok := data["nested"].(map[string]any)
	if !ok {
		t.Fatalf("data[nested] type = %T, want map[string]any", data["nested"])
	}
	if nested["ok"] != true {
		t.Fatalf("data[nested][ok] = %#v, want true", nested["ok"])
	}
	meta, ok := envelope.Meta.(map[string]any)
	if !ok {
		t.Fatalf("Meta type = %T, want map[string]any", envelope.Meta)
	}
	if meta["page"] != float64(1) {
		t.Fatalf("meta[page] = %#v, want float64(1)", meta["page"])
	}
}

func TestResponseUnmarshalRejectsMalformedEnvelope(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "truncated", body: `{"data":`},
		{name: "data not an object or value", body: `{"data":}`},
		{name: "error is not an object", body: `{"error":"boom"}`},
		{name: "trailing garbage", body: `{"data":1} oops`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var envelope Response
			if err := json.Unmarshal([]byte(tt.body), &envelope); err == nil {
				t.Fatalf("json.Unmarshal(%q) = nil error, want error; decoded %#v", tt.body, envelope)
			}
		})
	}
}

func TestAPIErrorRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		err  APIError
	}{
		{name: "zero value", err: APIError{}},
		{name: "code and message only", err: APIError{Code: "INVALID_CREDENTIALS", Message: "invalid username or password"}},
		{name: "with trace and event id", err: APIError{Code: "E", Message: "m", TraceID: "trace-1", EventID: "trace-1"}},
		{name: "message without code", err: APIError{Message: "only message"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.err)
			if err != nil {
				t.Fatalf("json.Marshal(%#v) returned error: %v", tt.err, err)
			}
			var got APIError
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("json.Unmarshal(%s) returned error: %v", raw, err)
			}
			if got != tt.err {
				t.Fatalf("round trip = %#v, want %#v", got, tt.err)
			}
		})
	}
}

func TestLoginRequestUnmarshal(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		want             LoginRequest
		wantErr          bool
		wantTypeErrField string
	}{
		{
			name: "all fields",
			body: `{"username":"admin","password":"s3cret","totp_code":"123456","captcha":{"mode":"pow","algorithm":"SHA-256"}}`,
			want: LoginRequest{
				Username: "admin",
				Password: "s3cret",
				TOTPCode: "123456",
				CAPTCHA:  &CAPTCHAPayload{Mode: "pow", Algorithm: "SHA-256"},
			},
		},
		{
			name:    "empty object leaves every field zero",
			body:    `{}`,
			want:    LoginRequest{},
			wantErr: false,
		},
		{
			name: "captcha explicitly null stays nil",
			body: `{"username":"admin","captcha":null}`,
			want: LoginRequest{Username: "admin"},
		},
		{
			name: "unknown fields are ignored",
			body: `{"username":"admin","is_admin":true,"nested":{"a":1}}`,
			want: LoginRequest{Username: "admin"},
		},
		{
			// The DTO does no validation or trimming: the console handler
			// owns that. Whitespace must survive verbatim.
			name: "whitespace and empty strings are preserved verbatim",
			body: `{"username":"  admin  ","password":"","totp_code":""}`,
			want: LoginRequest{Username: "  admin  "},
		},
		{
			name: "unicode username and password",
			body: `{"username":"管理员","password":"密 码 \"q\"","totp_code":"000000"}`,
			want: LoginRequest{Username: "管理员", Password: "密 码 \"q\"", TOTPCode: "000000"},
		},
		{
			name:             "username wrong type",
			body:             `{"username":42}`,
			wantErr:          true,
			wantTypeErrField: "username",
		},
		{
			name:             "password wrong type",
			body:             `{"password":["a"]}`,
			wantErr:          true,
			wantTypeErrField: "password",
		},
		{
			name:             "totp_code wrong type",
			body:             `{"totp_code":123456}`,
			wantErr:          true,
			wantTypeErrField: "totp_code",
		},
		{
			name:             "captcha not an object",
			body:             `{"captcha":"pow"}`,
			wantErr:          true,
			wantTypeErrField: "captcha",
		},
		{
			name:    "malformed json",
			body:    `{"username":`,
			wantErr: true,
		},
		{
			name:    "top level array",
			body:    `[]`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got LoginRequest
			err := json.Unmarshal([]byte(tt.body), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("json.Unmarshal(%q) = nil error, want error", tt.body)
				}
				if tt.wantTypeErrField != "" {
					if field := unmarshalTypeErrorField(err); field != tt.wantTypeErrField {
						t.Fatalf("error field = %q, want %q (err: %v)", field, tt.wantTypeErrField, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal(%q) returned error: %v", tt.body, err)
			}
			if got.Username != tt.want.Username || got.Password != tt.want.Password || got.TOTPCode != tt.want.TOTPCode {
				t.Fatalf("credentials = %+v, want %+v", got, tt.want)
			}
			if !reflect.DeepEqual(got.CAPTCHA, tt.want.CAPTCHA) {
				t.Fatalf("CAPTCHA = %#v, want %#v", got.CAPTCHA, tt.want.CAPTCHA)
			}
		})
	}
}

func TestLoginRequestMarshalEmitsCredentialsAlways(t *testing.T) {
	tests := []struct {
		name string
		req  LoginRequest
		want string
	}{
		{
			// username/password/totp_code carry no omitempty, so the
			// console always receives all three keys even when blank.
			name: "zero value emits all three credential keys",
			req:  LoginRequest{},
			want: `{"username":"","password":"","totp_code":""}`,
		},
		{
			name: "nil captcha is omitted",
			req:  LoginRequest{Username: "admin", Password: "pw"},
			want: `{"username":"admin","password":"pw","totp_code":""}`,
		},
		{
			name: "nested captcha payload",
			req: LoginRequest{
				Username: "admin",
				Password: "pw",
				TOTPCode: "123456",
				CAPTCHA:  &CAPTCHAPayload{Mode: "pow", Algorithm: "SHA-256", Number: 7},
			},
			want: `{"username":"admin","password":"pw","totp_code":"123456","captcha":{"mode":"pow","algorithm":"SHA-256","challenge":"","number":7,"salt":"","signature":""}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := marshalString(t, tt.req)
			if got != tt.want {
				t.Fatalf("json.Marshal(LoginRequest) = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCAPTCHAPayloadUnmarshal(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		want             CAPTCHAPayload
		wantErr          bool
		wantTypeErrField string
	}{
		{
			name: "pow payload",
			body: `{"mode":"pow","username":"admin","algorithm":"SHA-256","challenge":"c","number":12345,"salt":"s","signature":"sig","receipt":"r"}`,
			want: CAPTCHAPayload{
				Mode: "pow", Username: "admin", Algorithm: "SHA-256",
				Challenge: "c", Number: 12345, Salt: "s", Signature: "sig", Receipt: "r",
			},
		},
		{
			name: "payload without mode defaults to empty mode",
			body: `{"algorithm":"SHA-256","challenge":"c","number":5,"salt":"s","signature":"sig"}`,
			want: CAPTCHAPayload{Algorithm: "SHA-256", Challenge: "c", Number: 5, Salt: "s", Signature: "sig"},
		},
		{
			name: "empty object",
			body: `{}`,
			want: CAPTCHAPayload{},
		},
		{
			name: "slider sub payload",
			body: `{"mode":"slider","username":"admin","slider":{"token":"tok","x":42,"drag_ms":900,"track":"1,2,3"}}`,
			want: CAPTCHAPayload{
				Mode: "slider", Username: "admin",
				Slider: &SliderCAPTCHAPayload{Token: "tok", X: 42, DragMS: 900, Track: "1,2,3"},
			},
		},
		{
			name: "slider omitted when absent",
			body: `{"mode":"pow"}`,
			want: CAPTCHAPayload{Mode: "pow"},
		},
		{
			name: "slider explicitly null stays nil",
			body: `{"mode":"pow","slider":null}`,
			want: CAPTCHAPayload{Mode: "pow"},
		},
		{
			name: "negative number is accepted",
			body: `{"number":-1}`,
			want: CAPTCHAPayload{Number: -1},
		},
		{
			name: "unknown fields are ignored",
			body: `{"algorithm":"SHA-256","bogus":{"deep":[1,2]}}`,
			want: CAPTCHAPayload{Algorithm: "SHA-256"},
		},
		{
			name:             "number wrong type",
			body:             `{"number":"12345"}`,
			wantErr:          true,
			wantTypeErrField: "number",
		},
		{
			name:             "number not representable as int",
			body:             `{"number":1e30}`,
			wantErr:          true,
			wantTypeErrField: "number",
		},
		{
			name:             "slider wrong type",
			body:             `{"slider":[1,2]}`,
			wantErr:          true,
			wantTypeErrField: "slider",
		},
		{
			// Nested fields report their full path, e.g. slider.x.
			name:             "slider x wrong type",
			body:             `{"slider":{"x":"42"}}`,
			wantErr:          true,
			wantTypeErrField: "slider.x",
		},
		{
			name:             "slider drag_ms wrong type",
			body:             `{"slider":{"drag_ms":true}}`,
			wantErr:          true,
			wantTypeErrField: "slider.drag_ms",
		},
		{
			name:    "malformed json",
			body:    `{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got CAPTCHAPayload
			err := json.Unmarshal([]byte(tt.body), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("json.Unmarshal(%q) = nil error, want error", tt.body)
				}
				if tt.wantTypeErrField != "" {
					if field := unmarshalTypeErrorField(err); field != tt.wantTypeErrField {
						t.Fatalf("error field = %q, want %q (err: %v)", field, tt.wantTypeErrField, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal(%q) returned error: %v", tt.body, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CAPTCHAPayload = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestCAPTCHAPayloadMarshalOmitempty(t *testing.T) {
	tests := []struct {
		name    string
		payload CAPTCHAPayload
		want    string
	}{
		{
			// mode/receipt/username are optional; the proof fields are not.
			name:    "zero value emits proof fields only",
			payload: CAPTCHAPayload{},
			want:    `{"algorithm":"","challenge":"","number":0,"salt":"","signature":""}`,
		},
		{
			name:    "optional fields present",
			payload: CAPTCHAPayload{Mode: "pow", Receipt: "r", Username: "admin", Algorithm: "SHA-256", Number: 3},
			want:    `{"mode":"pow","receipt":"r","username":"admin","algorithm":"SHA-256","challenge":"","number":3,"salt":"","signature":""}`,
		},
		{
			name: "slider sub payload",
			payload: CAPTCHAPayload{
				Mode:   "slider",
				Slider: &SliderCAPTCHAPayload{Token: "tok", X: 42, DragMS: 900, Track: "1,2,3"},
			},
			want: `{"mode":"slider","algorithm":"","challenge":"","number":0,"salt":"","signature":"","slider":{"token":"tok","x":42,"drag_ms":900,"track":"1,2,3"}}`,
		},
		{
			name: "slider without track omits track",
			payload: CAPTCHAPayload{
				Mode:   "slider",
				Slider: &SliderCAPTCHAPayload{Token: "tok", X: 1, DragMS: 2},
			},
			want: `{"mode":"slider","algorithm":"","challenge":"","number":0,"salt":"","signature":"","slider":{"token":"tok","x":1,"drag_ms":2}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := marshalString(t, tt.payload)
			if got != tt.want {
				t.Fatalf("json.Marshal(CAPTCHAPayload) = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCAPTCHAPayloadRoundTrip(t *testing.T) {
	original := CAPTCHAPayload{
		Mode:      "slider",
		Receipt:   "receipt-value",
		Username:  "admin",
		Algorithm: "SHA-256",
		Challenge: "challenge-value",
		Number:    987654,
		Salt:      "salt-value",
		Signature: "signature-value",
		Slider: &SliderCAPTCHAPayload{
			Token:  "token-value",
			X:      123,
			DragMS: 456,
			Track:  "10,20,30",
		},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var decoded CAPTCHAPayload
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(%s) returned error: %v", raw, err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("round trip = %#v, want %#v", decoded, original)
	}
	if decoded.Slider == nil || decoded.Slider == original.Slider {
		t.Fatalf("Slider = %#v, want an equal but distinct pointer", decoded.Slider)
	}
}

func TestSliderCAPTCHAPayloadRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   SliderCAPTCHAPayload
	}{
		{name: "zero value", in: SliderCAPTCHAPayload{}},
		{name: "without track", in: SliderCAPTCHAPayload{Token: "tok", X: 10, DragMS: 200}},
		{name: "with track", in: SliderCAPTCHAPayload{Token: "tok", X: -5, DragMS: 0, Track: "1,2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("json.Marshal returned error: %v", err)
			}
			var got SliderCAPTCHAPayload
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("json.Unmarshal(%s) returned error: %v", raw, err)
			}
			if got != tt.in {
				t.Fatalf("round trip = %#v, want %#v", got, tt.in)
			}
		})
	}
}

func TestCAPTCHAChallengeRequestUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    CAPTCHAChallengeRequest
		wantErr bool
	}{
		{name: "empty object", body: `{}`, want: CAPTCHAChallengeRequest{}},
		{name: "pow mode", body: `{"mode":"pow"}`, want: CAPTCHAChallengeRequest{Mode: "pow"}},
		{name: "slider mode", body: `{"mode":"slider"}`, want: CAPTCHAChallengeRequest{Mode: "slider"}},
		{name: "unknown mode kept verbatim", body: `{"mode":"nope"}`, want: CAPTCHAChallengeRequest{Mode: "nope"}},
		{name: "null mode", body: `{"mode":null}`, want: CAPTCHAChallengeRequest{}},
		{name: "unknown field ignored", body: `{"mode":"pow","other":1}`, want: CAPTCHAChallengeRequest{Mode: "pow"}},
		{name: "wrong type", body: `{"mode":7}`, wantErr: true},
		{name: "malformed", body: `{"mode":`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got CAPTCHAChallengeRequest
			err := json.Unmarshal([]byte(tt.body), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("json.Unmarshal(%q) = nil error, want error", tt.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal(%q) returned error: %v", tt.body, err)
			}
			if got != tt.want {
				t.Fatalf("CAPTCHAChallengeRequest = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSetupRequestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		req  SetupRequest
		want string
	}{
		{
			// No field is optional, so a blank setup request still ships
			// every key explicitly.
			name: "zero value emits every key",
			req:  SetupRequest{},
			want: `{"username":"","password":"","admin_listen":"","admin_strategy":"","admin_public":false}`,
		},
		{
			name: "full request",
			req: SetupRequest{
				Username:      "admin",
				Password:      "pw",
				AdminListen:   "127.0.0.1:9090",
				AdminStrategy: "loopback",
				AdminPublic:   true,
			},
			want: `{"username":"admin","password":"pw","admin_listen":"127.0.0.1:9090","admin_strategy":"loopback","admin_public":true}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := marshalString(t, tt.req)
			if got != tt.want {
				t.Fatalf("json.Marshal(SetupRequest) = %s, want %s", got, tt.want)
			}
			var decoded SetupRequest
			if err := json.Unmarshal([]byte(got), &decoded); err != nil {
				t.Fatalf("json.Unmarshal(%s) returned error: %v", got, err)
			}
			if decoded != tt.req {
				t.Fatalf("round trip = %#v, want %#v", decoded, tt.req)
			}
		})
	}
}

func TestSetupRequestUnmarshalRejectsWrongTypes(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
	}{
		{name: "username", body: `{"username":1}`, field: "username"},
		{name: "password", body: `{"password":{}}`, field: "password"},
		{name: "admin_listen", body: `{"admin_listen":[]}`, field: "admin_listen"},
		{name: "admin_strategy", body: `{"admin_strategy":1}`, field: "admin_strategy"},
		{name: "admin_public", body: `{"admin_public":"yes"}`, field: "admin_public"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req SetupRequest
			err := json.Unmarshal([]byte(tt.body), &req)
			if err == nil {
				t.Fatalf("json.Unmarshal(%q) = nil error, want error", tt.body)
			}
			if field := unmarshalTypeErrorField(err); field != tt.field {
				t.Fatalf("error field = %q, want %q (err: %v)", field, tt.field, err)
			}
		})
	}
}
