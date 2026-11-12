package betterauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// maxBody caps a request body; auth requests are small.
const maxBody = 1 << 20

// requestContext is one request on its way through the pipeline.
type requestContext struct {
	r       *http.Request
	path    string         // path after the base path
	body    map[string]any // parsed body; nil when there was none
	rawBody any            // the decoded body before the object check
	hasBody bool
	cookies *setCookies
	header  http.Header // extra response headers (Location)
}

type route struct {
	methods  []string
	form     bool // also accepts application/x-www-form-urlencoded
	formCSRF bool // formCsrfMiddleware: login and sign-up
	handle   func(*Auth, *requestContext) (any, error)
}

var routes = map[string]route{
	"/sign-up/email": {methods: []string{http.MethodPost}, form: true, formCSRF: true, handle: (*Auth).signUpEmail},
	"/sign-in/email": {methods: []string{http.MethodPost}, form: true, formCSRF: true, handle: (*Auth).signInEmail},
	"/sign-out":      {methods: []string{http.MethodPost}, handle: (*Auth).signOut},
	"/get-session":   {methods: []string{http.MethodGet, http.MethodPost}, handle: (*Auth).getSession},
	"/ok":            {methods: []string{http.MethodGet}, handle: func(*Auth, *requestContext) (any, error) { return newObject().set("ok", true), nil }},
}

// Handler returns the HTTP handler for BasePath. Mount it with
// http.Handle(cfg.BasePath+"/", auth.Handler()); it reads the full request
// path, so no prefix stripping is needed.
func (a *Auth) Handler() http.Handler {
	return http.HandlerFunc(a.serve)
}

var jsonType = regexp.MustCompile(`(?i)^application/([a-z0-9.+-]*\+)?json`)

func (a *Auth) serve(w http.ResponseWriter, r *http.Request) {
	rc := &requestContext{r: r, cookies: &setCookies{}, header: http.Header{}}

	// The router strips the base path the way better-call does: split on it
	// and keep what follows the first occurrence.
	path, ok := a.relativePath(r.URL.Path)
	rc.path = path

	if a.limiter != nil {
		if blocked, retry := a.limiter.check(a.rateLimitIP(r), path); blocked {
			w.Header().Set("X-Retry-After", strconv.Itoa(retry))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"Too many requests. Please try again later."}`))
			a.limiter.record(a.rateLimitIP(r), path)
			return
		}
		defer a.limiter.record(a.rateLimitIP(r), path)
	}

	rt, found := routes[path]
	if !ok || !found || !allows(rt.methods, r.Method) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if apiErr, internal := a.parseBody(rc, rt); internal {
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else if apiErr != nil {
		a.respond(w, rc, nil, apiErr)
		return
	}
	if err := a.originCheck(rc); err != nil {
		a.respond(w, rc, nil, err)
		return
	}
	result, err := rt.handle(a, rc)
	a.respond(w, rc, result, err)
}

func allows(methods []string, m string) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

func (a *Auth) relativePath(p string) (string, bool) {
	parts := strings.Split(p, a.basePath)
	if len(parts) < 2 {
		return "", false
	}
	rest := strings.Join(parts[1:], a.basePath)
	if rest == "" || strings.Contains(p, "//") {
		return "", false
	}
	return rest, true
}

// parseBody reads the body as the library's getBody does. internal reports a
// body that cannot be decoded, which the library answers with an empty 500.
func (a *Auth) parseBody(rc *requestContext, rt route) (apiErr *APIError, internal bool) {
	r := rc.r
	if r.Body == nil || r.Body == http.NoBody || (r.ContentLength == 0 && len(r.TransferEncoding) == 0) {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return nil, true
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return nil, false // the library then sees an undefined body
	}
	allowed := []string{"application/json"}
	if rt.form {
		allowed = []string{"application/x-www-form-urlencoded", "application/json"}
	}
	switch {
	case jsonType.MatchString(ct):
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, true
		}
		rc.rawBody, rc.hasBody = v, true
	case rt.form && strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded"):
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			return nil, true
		}
		m := map[string]any{}
		for k, v := range vals {
			m[k] = v[len(v)-1]
		}
		rc.rawBody, rc.hasBody = m, true
	default:
		return &APIError{Status: http.StatusUnsupportedMediaType, Code: "UNSUPPORTED_MEDIA_TYPE",
			Message: fmt.Sprintf("Content-Type %q is not allowed. Allowed types: %s", ct, strings.Join(allowed, ", "))}, false
	}
	if m, ok := rc.rawBody.(map[string]any); ok {
		rc.body = m
	}
	return nil, false
}

// rateLimitIP keys the limiter. The library uses the first X-Forwarded-For
// entry and skips limiting without one (D15: here the connection's address
// is used instead, so a missing header does not switch limiting off).
func (a *Auth) rateLimitIP(r *http.Request) string {
	if ip := clientIP(r); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Auth) respond(w http.ResponseWriter, rc *requestContext, result any, err error) {
	rc.cookies.write(w.Header())
	for k, vs := range rc.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	var apiErr *APIError
	switch {
	case errors.As(err, &apiErr):
		writeError(w, apiErr)
	case err != nil:
		a.log.Error("request failed", "path", rc.path, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusOK, result)
	}
}

// --- origin and CSRF checks (api/middlewares/origin-check.ts) ---

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (a *Auth) trustedURL(raw string, allowRelative bool) bool {
	if allowRelative && strings.HasPrefix(raw, "/") {
		return safeRelativePath(raw)
	}
	o := originOf(raw)
	return o != "" && a.origins[o]
}

// safeRelativePath implements the library's relative-path pattern
// ^\/(?!\/|\\|%2f|%5c)[\w\-.\+/@]*(?:\?[\w\-.\+/=&%@]*)?$ without
// lookahead, which Go's regexp lacks.
func safeRelativePath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	rest := p[1:]
	low := strings.ToLower(rest)
	if strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, `\`) || strings.HasPrefix(low, "%2f") || strings.HasPrefix(low, "%5c") {
		return false
	}
	return safeRelativeBody.MatchString(rest)
}

var safeRelativeBody = regexp.MustCompile(`^[\w\-.+/@]*(?:\?[\w\-.+/=&%@]*)?$`)

// validateOrigin is the library's validateOrigin: with cookies (or when
// forced), the Origin or Referer must be trusted.
func (a *Auth) validateOrigin(r *http.Request, force bool) *APIError {
	if a.cfg.Advanced.DisableOriginCheck || a.cfg.Advanced.DisableCSRFCheck {
		return nil
	}
	if r.Header.Get("Cookie") == "" && !force {
		return nil
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" || origin == "null" {
		return apiError(http.StatusForbidden, "MISSING_OR_NULL_ORIGIN")
	}
	if !a.trustedURL(origin, false) {
		return apiError(http.StatusForbidden, "INVALID_ORIGIN")
	}
	return nil
}

// originCheck is originCheckMiddleware plus formCsrfMiddleware.
func (a *Auth) originCheck(rc *requestContext) *APIError {
	r := rc.r
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	if err := a.validateOrigin(r, false); err != nil {
		return err
	}
	if !a.cfg.Advanced.DisableOriginCheck {
		for _, f := range []struct{ field, code string }{
			{"callbackURL", "INVALID_CALLBACK_URL"},
			{"redirectTo", "INVALID_REDIRECT_URL"},
			{"errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"},
			{"newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL"},
		} {
			v, _ := rc.body[f.field].(string)
			if v == "" && f.field == "callbackURL" {
				v = r.URL.Query().Get("callbackURL")
			}
			if v != "" && !a.trustedURL(v, true) {
				return apiError(http.StatusForbidden, f.code)
			}
		}
	}
	return nil
}

// formCSRF is formCsrfMiddleware, run after body validation on sign-in and
// sign-up: without cookies it reads Fetch Metadata.
func (a *Auth) formCSRF(r *http.Request) *APIError {
	if a.cfg.Advanced.DisableOriginCheck || a.cfg.Advanced.DisableCSRFCheck {
		return nil
	}
	if r.Header.Get("Cookie") != "" {
		return a.validateOrigin(r, false)
	}
	site, mode, dest := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest")
	if site == "" && mode == "" && dest == "" {
		return nil
	}
	if site == "cross-site" && mode == "navigate" {
		return apiError(http.StatusForbidden, "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED")
	}
	return a.validateOrigin(r, true)
}
