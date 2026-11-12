package betterauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/cookie"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/crypto"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/jsuri"
)

// --- body validation with the library's (zod 4) messages ---

type fieldCheck struct {
	name     string
	kind     string // "string", "boolean" or "email"
	optional bool
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number, float64, int:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

// zodEmail is zod 4's default email pattern
// ^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$
// with the two lookaheads checked separately.
var zodEmailBody = regexp.MustCompile(`^([A-Za-z0-9_'+\-.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

func validEmail(s string) bool {
	return !strings.HasPrefix(s, ".") && !strings.Contains(s, "..") && zodEmailBody.MatchString(s)
}

// validate checks the body as the endpoint's zod schema does and returns the
// library's VALIDATION_ERROR with every issue, in schema order. record marks
// a schema intersected with z.record (sign-up), which reports a body that is
// not an object a second time.
func validate(rc *requestContext, checks []fieldCheck, record bool) *APIError {
	fail := func(issues []string) *APIError {
		return &APIError{Status: http.StatusBadRequest, Code: "VALIDATION_ERROR", Message: strings.Join(issues, "; ")}
	}
	if rc.body == nil {
		got := "undefined"
		if rc.hasBody {
			got = typeName(rc.rawBody)
		}
		issues := []string{"[body] Invalid input: expected object, received " + got}
		if record {
			issues = append(issues, "[body] Invalid input: expected record, received "+got)
		}
		return fail(issues)
	}
	var issues []string
	for _, c := range checks {
		v, present := rc.body[c.name]
		if !present {
			if !c.optional {
				issues = append(issues, "[body."+c.name+"] Invalid input: expected "+expected(c.kind)+", received undefined")
			}
			continue
		}
		got := typeName(v)
		if got != expected(c.kind) {
			issues = append(issues, "[body."+c.name+"] Invalid input: expected "+expected(c.kind)+", received "+got)
			continue
		}
		if c.kind == "email" && !validEmail(v.(string)) {
			issues = append(issues, "[body."+c.name+"] Invalid email address")
		}
	}
	if len(issues) > 0 {
		return fail(issues)
	}
	return nil
}

func expected(kind string) string {
	if kind == "email" {
		return "string"
	}
	return kind
}

func str(body map[string]any, k string) string {
	s, _ := body[k].(string)
	return s
}

// rememberMeFalse reports rememberMe === false; absent means true.
func rememberMeFalse(body map[string]any) bool {
	b, ok := body["rememberMe"].(bool)
	return ok && !b
}

// --- POST /sign-up/email (api/routes/sign-up.ts) ---

func (a *Auth) signUpEmail(rc *requestContext) (any, error) {
	if err := validate(rc, []fieldCheck{
		{"name", "string", false}, {"email", "email", false}, {"password", "string", false},
		{"image", "string", true}, {"callbackURL", "string", true}, {"rememberMe", "boolean", true},
	}, true); err != nil {
		return nil, err
	}
	if err := a.formCSRF(rc.r); err != nil {
		return nil, err
	}
	ep := a.cfg.EmailAndPassword
	if !ep.Enabled || ep.DisableSignUp {
		return nil, apiError(http.StatusBadRequest, "EMAIL_PASSWORD_SIGN_UP_DISABLED")
	}
	body := rc.body
	password := str(body, "password")
	if n := jsuri.UTF16Len(password); n < ep.MinPasswordLength {
		return nil, apiError(http.StatusBadRequest, "PASSWORD_TOO_SHORT")
	} else if n > ep.MaxPasswordLength {
		return nil, apiError(http.StatusBadRequest, "PASSWORD_TOO_LONG")
	}
	ctx := rc.r.Context()
	email := jsuri.ToLowerCase(str(body, "email"))
	users := a.model("user")

	_, err := users.findOne(ctx, a.store, Where{Column: "email", Value: email})
	switch {
	case err == nil:
		a.log.Info("sign-up attempt for an existing email")
		if a.cfg.Compat.RevealExistingEmail {
			return nil, apiError(http.StatusUnprocessableEntity, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
		}
		return a.syntheticSignUp(email, body, password)
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}

	hash, err := crypto.HashPassword(a.rand, password)
	if err != nil {
		return nil, err
	}
	now := a.nowMs()
	var user *object
	err = a.store.Transaction(ctx, func(tx Store) error {
		data := map[string]any{"name": str(body, "name"), "email": email, "emailVerified": false,
			"createdAt": now, "updatedAt": now}
		if img, ok := body["image"].(string); ok {
			data["image"] = img
		}
		u, err := users.create(ctx, tx, data)
		if err != nil {
			return err
		}
		user = u
		_, err = a.model("account").create(ctx, tx, map[string]any{
			"accountId": stringOf(u, "id"), "providerId": "credential", "userId": stringOf(u, "id"),
			"password": hash, "createdAt": now, "updatedAt": now,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if !*ep.AutoSignIn {
		return newObject().set("token", nil).set("user", user), nil
	}
	dontRemember := rememberMeFalse(body)
	session, err := a.createSession(ctx, a.store, rc.r, stringOf(user, "id"), dontRemember)
	if err != nil {
		return nil, apiError(http.StatusBadRequest, "FAILED_TO_CREATE_SESSION")
	}
	if err := a.setSessionCookie(rc.cookies, stringOf(session, "token"), dontRemember, nil); err != nil {
		return nil, err
	}
	return newObject().set("token", stringOf(session, "token")).set("user", user), nil
}

// syntheticSignUp is the library's generic duplicate response (D9): the
// password is hashed anyway so timing does not tell, and a made-up user with
// no session comes back.
func (a *Auth) syntheticSignUp(email string, body map[string]any, password string) (any, error) {
	if _, err := crypto.HashPassword(a.rand, password); err != nil {
		return nil, err
	}
	id, err := a.generateID()
	if err != nil {
		return nil, err
	}
	now := jsTime(a.nowMs())
	var image any
	if img, ok := body["image"].(string); ok {
		image = img
	}
	user := newObject().set("name", str(body, "name")).set("email", email).set("emailVerified", false).
		set("image", image).set("createdAt", now).set("updatedAt", now).set("id", id)
	return newObject().set("token", nil).set("user", user), nil
}

// --- POST /sign-in/email (api/routes/sign-in.ts) ---

func (a *Auth) signInEmail(rc *requestContext) (any, error) {
	if err := validate(rc, []fieldCheck{
		{"email", "string", false}, {"password", "string", false},
		{"callbackURL", "string", true}, {"rememberMe", "boolean", true},
	}, false); err != nil {
		return nil, err
	}
	if err := a.formCSRF(rc.r); err != nil {
		return nil, err
	}
	if !a.cfg.EmailAndPassword.Enabled {
		return nil, apiError(http.StatusBadRequest, "EMAIL_PASSWORD_DISABLED")
	}
	body := rc.body
	if !validEmail(str(body, "email")) {
		return nil, apiError(http.StatusBadRequest, "INVALID_EMAIL")
	}
	ctx := rc.r.Context()
	password := str(body, "password")
	invalid := apiError(http.StatusUnauthorized, "INVALID_EMAIL_OR_PASSWORD")

	user, hash, err := a.credentialUser(ctx, jsuri.ToLowerCase(str(body, "email")))
	if err != nil {
		return nil, err
	}
	if user == nil || hash == "" {
		// Hash anyway so an unknown address takes as long as a wrong password.
		if _, err := crypto.HashPassword(a.rand, password); err != nil {
			return nil, err
		}
		return nil, invalid
	}
	ok, err := crypto.VerifyPassword(hash, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, invalid
	}

	dontRemember := rememberMeFalse(body)
	session, err := a.createSession(ctx, a.store, rc.r, stringOf(user, "id"), dontRemember)
	if err != nil {
		a.log.Error("creating a session", "error", err)
		return nil, apiError(http.StatusUnauthorized, "FAILED_TO_CREATE_SESSION")
	}
	if err := a.setSessionCookie(rc.cookies, stringOf(session, "token"), dontRemember, nil); err != nil {
		return nil, err
	}
	callback := str(body, "callbackURL")
	out := newObject().set("redirect", callback != "").set("token", stringOf(session, "token"))
	if callback != "" {
		rc.header.Set("Location", callback)
		out.set("url", callback)
	}
	return out.set("user", user), nil
}

// credentialUser finds a user by email with the password of their credential
// account; hash is empty when they have none.
func (a *Auth) credentialUser(ctx context.Context, email string) (*object, string, error) {
	user, err := a.model("user").findOne(ctx, a.store, Where{Column: "email", Value: email})
	if errors.Is(err, ErrNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	account, err := a.model("account").findOne(ctx, a.store,
		Where{Column: "userId", Value: stringOf(user, "id")}, Where{Column: "providerId", Value: "credential"})
	if errors.Is(err, ErrNotFound) {
		return user, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return user, stringOf(account, "password"), nil
}

// --- POST /sign-out (api/routes/sign-out.ts) ---

func (a *Auth) signOut(rc *requestContext) (any, error) {
	if token, state := a.sessionToken(rc.r); state == cookie.Valid {
		if err := a.model("session").deleteMany(rc.r.Context(), a.store, Where{Column: "token", Value: token}); err != nil {
			a.log.Error("deleting a session on sign-out", "error", err)
		}
	}
	a.deleteSessionCookie(rc.cookies, rc.r)
	return newObject().set("success", true), nil
}
