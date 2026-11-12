package betterauth

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// APIError is an error the API answers with: an HTTP status and the
// library's {"message","code"} body.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// errorMessages are better-auth's BASE_ERROR_CODES (core/src/error/codes.ts),
// plus the router's own codes.
var errorMessages = map[string]string{
	"USER_NOT_FOUND":                            "User not found",
	"FAILED_TO_CREATE_USER":                     "Failed to create user",
	"FAILED_TO_CREATE_SESSION":                  "Failed to create session",
	"FAILED_TO_UPDATE_USER":                     "Failed to update user",
	"FAILED_TO_GET_SESSION":                     "Failed to get session",
	"INVALID_PASSWORD":                          "Invalid password",
	"INVALID_EMAIL":                             "Invalid email",
	"INVALID_EMAIL_OR_PASSWORD":                 "Invalid email or password",
	"INVALID_USER":                              "Invalid user",
	"INVALID_TOKEN":                             "Invalid token",
	"TOKEN_EXPIRED":                             "Token expired",
	"EMAIL_NOT_VERIFIED":                        "Email not verified",
	"PASSWORD_TOO_SHORT":                        "Password too short",
	"PASSWORD_TOO_LONG":                         "Password too long",
	"USER_ALREADY_EXISTS":                       "User already exists.",
	"USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL":     "User already exists. Use another email.",
	"CREDENTIAL_ACCOUNT_NOT_FOUND":              "Credential account not found",
	"SESSION_EXPIRED":                           "Session expired. Re-authenticate to perform this action.",
	"CROSS_SITE_NAVIGATION_LOGIN_BLOCKED":       "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
	"INVALID_ORIGIN":                            "Invalid origin",
	"INVALID_CALLBACK_URL":                      "Invalid callbackURL",
	"INVALID_REDIRECT_URL":                      "Invalid redirectURL",
	"INVALID_ERROR_CALLBACK_URL":                "Invalid errorCallbackURL",
	"INVALID_NEW_USER_CALLBACK_URL":             "Invalid newUserCallbackURL",
	"MISSING_OR_NULL_ORIGIN":                    "Missing or null Origin",
	"VALIDATION_ERROR":                          "Validation Error",
	"METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED": "POST method requires deferSessionRefresh to be enabled in session config",
	"EMAIL_PASSWORD_SIGN_UP_DISABLED":           "Email and password sign up is not enabled",
	"EMAIL_PASSWORD_DISABLED":                   "Email and password is not enabled",
}

// apiError builds an error with the library's message for code.
func apiError(status int, code string) *APIError {
	return &APIError{Status: status, Code: code, Message: errorMessages[code]}
}

// object is a JSON object that keeps its key order, as JavaScript objects
// do. Responses list fields in the library's order.
type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

// set adds or replaces a key; a new key goes last.
func (o *object) set(k string, v any) *object {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *object) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

// MarshalJSON writes the keys in order.
func (o *object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// writeJSON writes v with the library's content type. A nil v writes null.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, e *APIError) {
	writeJSON(w, e.Status, newObject().set("message", e.Message).set("code", e.Code))
}
