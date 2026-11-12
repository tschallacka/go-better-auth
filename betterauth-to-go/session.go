package betterauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/cookie"
)

// ErrNoSession is returned by ResolveSession when the request carries no
// valid, unexpired session.
var ErrNoSession = errors.New("betterauth: no session")

// SessionInfo is a resolved session and its user. Fields holds every stored
// field by logical name, additional fields included.
type SessionInfo struct {
	Session Session
	User    User
}

// Session is one session row.
type Session struct {
	ID        string
	Token     string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	IPAddress string
	UserAgent string
	Fields    map[string]any
}

// User is one user row.
type User struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Fields        map[string]any
}

func fieldsOf(o *object) map[string]any {
	out := make(map[string]any, len(o.keys))
	for _, k := range o.keys {
		v := o.vals[k]
		if t, ok := v.(jsTime); ok {
			v = time.Time(t)
		}
		out[k] = v
	}
	return out
}

func sessionFrom(o *object) Session {
	s := Session{ID: stringOf(o, "id"), Token: stringOf(o, "token"), UserID: stringOf(o, "userId"),
		IPAddress: stringOf(o, "ipAddress"), UserAgent: stringOf(o, "userAgent"), Fields: fieldsOf(o)}
	s.ExpiresAt, _ = timeOf(o, "expiresAt")
	s.CreatedAt, _ = timeOf(o, "createdAt")
	s.UpdatedAt, _ = timeOf(o, "updatedAt")
	return s
}

func userFrom(o *object) User {
	u := User{ID: stringOf(o, "id"), Name: stringOf(o, "name"), Email: stringOf(o, "email"),
		Image: stringOf(o, "image"), Fields: fieldsOf(o)}
	u.EmailVerified, _ = o.vals["emailVerified"].(bool)
	u.CreatedAt, _ = timeOf(o, "createdAt")
	u.UpdatedAt, _ = timeOf(o, "updatedAt")
	return u
}

// clientIP is the library's getIp in production: the first entry of
// X-Forwarded-For when it is a valid IP, normalised (normalizeIP), otherwise
// empty. Like the library it trusts the header, so the service must sit
// behind a proxy that sets it (DIVERGENCES.md, D15).
func (a *Auth) clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return ""
	}
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	ip, ok := normalizeIP(first, a.ipv6Subnet())
	if !ok {
		return ""
	}
	return ip
}

func (a *Auth) ipv6Subnet() int {
	if a.cfg.Advanced.IPv6Subnet != nil {
		return *a.cfg.Advanced.IPv6Subnet
	}
	return 64
}

// normalizeIP follows the library's normalizeIP (core/src/utils/ip.ts): IPv4
// as written, IPv4-mapped IPv6 (::ffff:a.b.c.d) as IPv4, any other IPv6
// masked to its /subnet and written as eight lowercase four-digit groups, so
// clients that rotate addresses inside one /64 are limited together. Only
// true ::ffff: mappings count as IPv4; the library's looser check also maps
// some non-mapped forms, one of them wrongly (D19).
func normalizeIP(s string, subnet int) (string, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	if addr.Is4() {
		return addr.String(), true
	}
	if addr.Is4In6() {
		return addr.Unmap().String(), true
	}
	if subnet < 0 {
		subnet = 0
	}
	if subnet < 128 {
		p, err := addr.Prefix(subnet)
		if err != nil {
			return "", false
		}
		addr = p.Addr()
	}
	b := addr.As16()
	groups := make([]string, 8)
	for i := range groups {
		groups[i] = fmt.Sprintf("%02x%02x", b[2*i], b[2*i+1])
	}
	return strings.Join(groups, ":"), true
}

// createSession writes a session for userID, as internalAdapter.createSession.
func (a *Auth) createSession(ctx context.Context, s Store, r *http.Request, userID string, dontRememberMe bool) (*object, error) {
	token, err := a.generateID()
	if err != nil {
		return nil, err
	}
	now := a.nowMs()
	life := a.cfg.Session.ExpiresIn
	if dontRememberMe {
		life = 24 * time.Hour
	}
	return a.model("session").create(ctx, s, map[string]any{
		"expiresAt": now.Add(life),
		"token":     token,
		"createdAt": now,
		"updatedAt": now,
		"ipAddress": a.clientIP(r),
		"userAgent": r.UserAgent(),
		"userId":    userID,
	})
}

// findSession looks a session up by token with its user. It returns
// ErrNotFound when either is missing.
func (a *Auth) findSession(ctx context.Context, token string) (session, user *object, err error) {
	session, err = a.model("session").findOne(ctx, a.store, Where{Column: "token", Value: token})
	if err != nil {
		return nil, nil, err
	}
	user, err = a.model("user").findOne(ctx, a.store, Where{Column: "id", Value: stringOf(session, "userId")})
	if err != nil {
		return nil, nil, err
	}
	return session, user, nil
}

// ResolveSession returns the session the request's cookie belongs to, for an
// application's own middleware. It reads only: no refresh, no cookies.
func (a *Auth) ResolveSession(r *http.Request) (*SessionInfo, error) {
	token, state := a.sessionToken(r)
	if state != cookie.Valid {
		return nil, ErrNoSession
	}
	session, user, err := a.findSession(r.Context(), token)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	if exp, _ := timeOf(session, "expiresAt"); !exp.After(a.now()) {
		return nil, ErrNoSession
	}
	return &SessionInfo{Session: sessionFrom(session), User: userFrom(user)}, nil
}

// getSession is GET /get-session (api/routes/session.ts).
func (a *Auth) getSession(rc *requestContext) (any, error) {
	if rc.r.Method == http.MethodPost {
		return nil, apiError(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED")
	}
	token, state := a.sessionToken(rc.r)
	if state != cookie.Valid {
		return nil, nil // 200 null, cookies left alone
	}
	ctx := rc.r.Context()
	session, user, err := a.findSession(ctx, token)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := a.now()
	if err != nil || !mustTime(session, "expiresAt").After(now) {
		a.deleteSessionCookie(rc.cookies, rc.r)
		if session != nil {
			if err := a.model("session").deleteMany(ctx, a.store, Where{Column: "token", Value: token}); err != nil {
				a.log.Error("deleting an expired session", "error", err)
			}
		}
		return nil, nil
	}

	_, disable := rc.r.URL.Query()["disableRefresh"]
	if disable {
		// z.coerce.boolean: any non-empty value is true, "false" included.
		disable = rc.r.URL.Query().Get("disableRefresh") != ""
	}
	if a.dontRememberSet(rc.r) || disable || a.cfg.Session.DisableSessionRefresh {
		return newObject().set("session", session).set("user", user), nil
	}

	expiresAt := mustTime(session, "expiresAt")
	due := !expiresAt.Add(-a.cfg.Session.ExpiresIn).Add(a.cfg.Session.UpdateAge).After(now)
	if !due {
		return newObject().set("session", session).set("user", user), nil
	}
	newExpiry := a.nowMs().Add(a.cfg.Session.ExpiresIn)
	updated, err := a.model("session").update(ctx, a.store, map[string]any{"expiresAt": newExpiry},
		Where{Column: "token", Value: token})
	if errors.Is(err, ErrNotFound) {
		a.deleteSessionCookie(rc.cookies, rc.r)
		return nil, apiError(http.StatusUnauthorized, "FAILED_TO_GET_SESSION")
	}
	if err != nil {
		return nil, err
	}
	// Max-Age from the clock after the write, as the library computes it:
	// usually one second short of ExpiresIn.
	maxAge := int(newExpiry.Sub(a.now()) / time.Second)
	if err := a.setSessionCookie(rc.cookies, token, false, &maxAge); err != nil {
		return nil, err
	}
	return newObject().set("session", updated).set("user", user), nil
}

func mustTime(o *object, field string) time.Time {
	t, _ := timeOf(o, field)
	return t
}
