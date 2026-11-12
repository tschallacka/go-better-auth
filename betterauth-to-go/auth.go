package betterauth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/schema"
)

// Config mirrors the parts of better-auth's options this module supports.
// Zero values mean the library's defaults, except where noted. New rejects
// options it does not support rather than ignoring them.
type Config struct {
	// Secret signs cookies and encrypts stored secrets. It must be the value
	// the TypeScript deployment uses (BETTER_AUTH_SECRET). Required.
	Secret string
	// BaseURL is the application's origin, e.g. https://app.example.com, as
	// in better-auth's baseURL. Required.
	BaseURL string
	// BasePath is where the endpoints are mounted. Default "/api/auth".
	BasePath string
	// TrustedOrigins are accepted in addition to BaseURL's origin.
	TrustedOrigins []string

	EmailAndPassword EmailAndPassword
	Session          SessionOptions
	Advanced         Advanced
	RateLimit        RateLimitOptions

	// Schema holds model and column names and additional fields, as in the
	// library's user/session/account/verification options.
	Schema schema.Options

	// Compat restores library behaviour that this module tightens by default
	// (DIVERGENCES.md).
	Compat Compat
}

// EmailAndPassword configures email and password sign-in.
type EmailAndPassword struct {
	Enabled           bool
	DisableSignUp     bool
	MinPasswordLength int   // default 8
	MaxPasswordLength int   // default 128
	AutoSignIn        *bool // default true: sign-up creates a session
	// RequireEmailVerification is not supported yet; New rejects it.
	RequireEmailVerification bool
}

// SessionOptions configures sessions.
type SessionOptions struct {
	ExpiresIn             time.Duration // default 7 days
	UpdateAge             time.Duration // default 1 day
	DisableSessionRefresh bool
	// DeferSessionRefresh allows POST /get-session; not supported yet.
	DeferSessionRefresh bool
}

// Advanced mirrors the library's advanced options.
type Advanced struct {
	// UseSecureCookies forces the Secure flag and __Secure- prefix on or off;
	// nil decides from BaseURL's scheme.
	UseSecureCookies *bool
	CookiePrefix     string // default "better-auth"
	// DisableOriginCheck and DisableCSRFCheck switch off request origin
	// validation. Off by default; only for trusted, non-browser callers.
	DisableOriginCheck bool
	DisableCSRFCheck   bool
	// IPv6Subnet is the prefix IPv6 client addresses are collapsed to for
	// rate limiting and the session's ipAddress, as the library's
	// ipAddress.ipv6Subnet. nil means 64; 128 keeps whole addresses.
	IPv6Subnet *int
}

// RateLimitOptions configures rate limiting (D11). It is on by default: the
// library enables it only when NODE_ENV is production, and this module has
// no other mode.
type RateLimitOptions struct {
	Disabled bool
	Window   time.Duration // default 10 seconds
	Max      int           // default 100 requests per window
	// Store holds the counters. The default is in process memory, which is
	// per instance; several instances need a shared store.
	Store RateLimitStore
}

// Compat restores library behaviour this module tightens by default.
type Compat struct {
	// RevealExistingEmail answers sign-up for a registered email with 422
	// USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL, as the library does by default
	// (D9). Without it sign-up answers the library's generic response.
	RevealExistingEmail bool
}

// Option changes how an Auth runs: its clock, randomness and logging.
type Option func(*Auth)

// WithClock replaces the clock (tests).
func WithClock(now func() time.Time) Option { return func(a *Auth) { a.now = now } }

// WithRandom replaces the random source (tests).
func WithRandom(r io.Reader) Option { return func(a *Auth) { a.rand = r } }

// WithLogger sets the logger. Secrets and tokens are never logged.
func WithLogger(l *slog.Logger) Option { return func(a *Auth) { a.log = l } }

// Auth serves the better-auth HTTP API over a Store.
type Auth struct {
	cfg      Config
	store    Store
	schema   schema.Schema
	secret   []byte
	baseURL  *url.URL // BaseURL with BasePath: the library's ctx.baseURL
	basePath string
	origins  map[string]bool
	cookies  cookieSet
	limiter  *rateLimiter
	now      func() time.Time
	rand     io.Reader
	log      *slog.Logger
}

// New validates cfg and returns an Auth. store is the project's own; Auth
// never creates or alters tables (use pgstore.CheckSchema at startup).
func New(cfg Config, store Store, opts ...Option) (*Auth, error) {
	if store == nil {
		return nil, errors.New("betterauth: store is nil")
	}
	if cfg.Secret == "" {
		return nil, errors.New("betterauth: Secret is required")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("betterauth: BaseURL %q must be an absolute http or https URL", cfg.BaseURL)
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	if !strings.HasPrefix(cfg.BasePath, "/") {
		return nil, fmt.Errorf("betterauth: BasePath %q must start with /", cfg.BasePath)
	}

	ep := &cfg.EmailAndPassword
	if ep.MinPasswordLength == 0 {
		ep.MinPasswordLength = 8
	}
	if ep.MaxPasswordLength == 0 {
		ep.MaxPasswordLength = 128
	}
	if ep.MinPasswordLength < 1 || ep.MaxPasswordLength < ep.MinPasswordLength {
		return nil, errors.New("betterauth: password length limits are inconsistent")
	}
	if ep.AutoSignIn == nil {
		t := true
		ep.AutoSignIn = &t
	}
	if ep.RequireEmailVerification {
		return nil, errors.New("betterauth: EmailAndPassword.RequireEmailVerification is not supported yet")
	}
	if cfg.Session.ExpiresIn == 0 {
		cfg.Session.ExpiresIn = 7 * 24 * time.Hour
	}
	if cfg.Session.UpdateAge == 0 {
		cfg.Session.UpdateAge = 24 * time.Hour
	}
	if cfg.Session.DeferSessionRefresh {
		return nil, errors.New("betterauth: Session.DeferSessionRefresh is not supported yet")
	}
	if cfg.Advanced.CookiePrefix == "" {
		cfg.Advanced.CookiePrefix = "better-auth"
	}
	if cfg.RateLimit.Window == 0 {
		cfg.RateLimit.Window = 10 * time.Second
	}
	if cfg.RateLimit.Max == 0 {
		cfg.RateLimit.Max = 100
	}
	if cfg.RateLimit.Store == nil {
		cfg.RateLimit.Store = NewMemoryRateLimitStore()
	}
	if len(cfg.Schema.Plugins) > 0 {
		return nil, fmt.Errorf("betterauth: plugin %q is not supported yet", cfg.Schema.Plugins[0].ID)
	}
	if n := len(cfg.Schema.User.Additional) + len(cfg.Schema.Session.Additional) +
		len(cfg.Schema.Account.Additional) + len(cfg.Schema.Verification.Additional); n > 0 {
		return nil, errors.New("betterauth: additional fields are not supported yet")
	}

	a := &Auth{
		cfg:      cfg,
		store:    store,
		schema:   schema.Build(cfg.Schema),
		secret:   []byte(cfg.Secret),
		basePath: strings.TrimSuffix(cfg.BasePath, "/"),
		now:      time.Now,
		rand:     rand.Reader,
		log:      slog.New(slog.DiscardHandler),
	}
	full := *base
	full.Path = strings.TrimSuffix(base.Path, "/") + a.basePath
	a.baseURL = &full

	a.origins = map[string]bool{base.Scheme + "://" + base.Host: true}
	for _, o := range cfg.TrustedOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("betterauth: trusted origin %q is not an origin", o)
		}
		a.origins[u.Scheme+"://"+u.Host] = true
	}

	secure := base.Scheme == "https"
	if cfg.Advanced.UseSecureCookies != nil {
		secure = *cfg.Advanced.UseSecureCookies
	}
	a.cookies = newCookieSet(cfg.Advanced.CookiePrefix, secure, cfg.Session.ExpiresIn)

	for _, o := range opts {
		o(a)
	}
	a.limiter = newRateLimiter(cfg.RateLimit, a.now)
	return a, nil
}
