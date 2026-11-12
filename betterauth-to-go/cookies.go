package betterauth

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/cookie"
)

// cookieSet holds the names and attributes of the library's cookies
// (cookies/index.ts getCookies).
type cookieSet struct {
	secure         bool
	sessionToken   string
	sessionData    string
	dontRemember   string
	sessionMaxAge  int
	sessionDataAge int
}

func newCookieSet(prefix string, secure bool, expiresIn time.Duration) cookieSet {
	name := func(n string) string {
		if secure {
			return cookie.SecurePrefix + prefix + "." + n
		}
		return prefix + "." + n
	}
	return cookieSet{
		secure:         secure,
		sessionToken:   name("session_token"),
		sessionData:    name("session_data"),
		dontRemember:   name("dont_remember"),
		sessionMaxAge:  int(expiresIn / time.Second),
		sessionDataAge: 300,
	}
}

func (c cookieSet) options(maxAge *int) cookie.Options {
	return cookie.Options{Path: "/", HTTPOnly: true, SameSite: "lax", Secure: c.secure, MaxAge: maxAge}
}

// setCookies collects the Set-Cookie headers of one response in order, so a
// later expiry of a name can drop what was set for it earlier, as the
// library's expireCookie does.
type setCookies struct {
	names   []string
	headers []string
}

func (s *setCookies) add(name, header string) {
	s.names = append(s.names, name)
	s.headers = append(s.headers, header)
}

func (s *setCookies) expire(name, header string) {
	for i := 0; i < len(s.names); {
		if s.names[i] == name {
			s.names = append(s.names[:i], s.names[i+1:]...)
			s.headers = append(s.headers[:i], s.headers[i+1:]...)
			continue
		}
		i++
	}
	s.add(name, header)
}

func (s *setCookies) write(h http.Header) {
	for _, v := range s.headers {
		h.Add("Set-Cookie", v)
	}
}

// setSessionCookie is the library's setSessionCookie with the cookie cache
// off: the signed token, and with dontRememberMe a session-length cookie
// plus a signed dont_remember marker.
func (a *Auth) setSessionCookie(out *setCookies, token string, dontRememberMe bool, maxAge *int) error {
	if maxAge == nil && !dontRememberMe {
		age := a.cookies.sessionMaxAge
		maxAge = &age
	}
	if dontRememberMe {
		maxAge = nil
	}
	h, err := cookie.SerializeSigned(a.cookies.sessionToken, token, a.secret, a.cookies.options(maxAge), a.now())
	if err != nil {
		return err
	}
	out.add(a.cookies.sessionToken, h)
	if dontRememberMe {
		h, err := cookie.SerializeSigned(a.cookies.dontRemember, "true", a.secret, a.cookies.options(nil), a.now())
		if err != nil {
			return err
		}
		out.add(a.cookies.dontRemember, h)
	}
	return nil
}

func (a *Auth) expireCookie(out *setCookies, name string) {
	zero := 0
	h, err := cookie.Serialize(name, "", a.cookies.options(&zero), a.now())
	if err == nil {
		out.expire(name, h)
	}
}

// deleteSessionCookie is the library's deleteSessionCookie: the token, the
// cache cookie, every cache chunk the browser sent, then dont_remember.
func (a *Auth) deleteSessionCookie(out *setCookies, r *http.Request) {
	a.expireCookie(out, a.cookies.sessionToken)
	a.expireCookie(out, a.cookies.sessionData)
	var chunks []string
	for name := range cookie.Parse(strings.Join(r.Header.Values("Cookie"), "; ")) {
		if strings.HasPrefix(name, a.cookies.sessionData) {
			chunks = append(chunks, name)
		}
	}
	sort.Strings(chunks)
	for _, name := range chunks {
		zero := 0
		if h, err := cookie.Serialize(name, "", a.cookies.options(&zero), a.now()); err == nil {
			out.add(name, h) // appended, as the library appends chunk expiries
		}
	}
	a.expireCookie(out, a.cookies.dontRemember)
}

// requestCookies parses the request's Cookie header the way better-call does.
func requestCookies(r *http.Request) map[string]string {
	return cookie.Parse(strings.Join(r.Header.Values("Cookie"), "; "))
}

// sessionToken reads the signed session token from the request.
func (a *Auth) sessionToken(r *http.Request) (string, cookie.SignedState) {
	return cookie.GetSigned(requestCookies(r), a.cookies.sessionToken, cookie.NoPrefix, a.secret)
}

// dontRememberSet reports a valid signed dont_remember cookie.
func (a *Auth) dontRememberSet(r *http.Request) bool {
	v, state := cookie.GetSigned(requestCookies(r), a.cookies.dontRemember, cookie.NoPrefix, a.secret)
	return state == cookie.Valid && v != ""
}
