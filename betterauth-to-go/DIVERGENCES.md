# Divergences from better-auth 1.6.14

No code exists yet. The Owner chose "tightened" on 2026-11-09 for the library weaknesses D1 to D8, D10 and D12 in PLAN.md section 10. D9 and D11 stay as the library has them. Taskmanager (taskmanager-maintenance) reviewed the list; their conditions are included. Each entry gets its tests when implemented.

| # | Library behaviour | Go behaviour | Reason and conditions |
|---|---|---|---|
| D1 | id_token of Google and generic OIDC decoded without signature check | verified against the provider JWKS | forged id_token would sign anyone in |
| D2 | generic OIDC explicit link skips trusted-provider and verified-email check | check applied | account takeover by linking |
| D3 | OIDC iss check optional | id_token iss checked against discovery; the RFC 9207 response parameter is checked only when discovery declares authorization_response_iss_parameter_supported | many IdPs omit the parameter |
| D4 | no TOTP replay tracking | last accepted step per user kept in process memory for the validity window | no schema change allowed; holds only on Go-served requests during the overlap |
| D5 | expired 2FA cookie may work once | rejected | expiry must hold |
| D6 | re-enable 2FA regenerates secret with password only | current TOTP required only when twoFactorEnabled is true | abandoned setups must not get stuck |
| D7 | any member reads all invitations, roles and every organization additional field | invitations and role reads restricted for plain members; additional fields stay readable by members unless declared member-hidden (a per-field setting; joinCode is Taskmanager's own field, not better-auth's, and its team page shows it to every member) | Taskmanager does not rely on invitation or role reads |
| D8 | accept-invitation has no already-member check | checked in code, no schema change | duplicate member rows |
| D9 | sign-up returns 422 for an existing email (reveals the account) | non-revealing response by default; `Compat.RevealExistingEmail` restores the library behaviour | security and reusability rank above parity (PLAN.md 1.2); wire-visible, so Taskmanager is told before it ships |
| D11 | rate limits are per process, in memory | pluggable `RateLimitStore`, memory default, shared store supplied by the project | per-process counters are bypassed by running several instances; no schema change from this module |
| D10 | check-verification-otp distinguishes USER_NOT_FOUND from INVALID_OTP | one uniform error | account enumeration; Taskmanager does not call this endpoint |
| D12 | password hash compared with plain === | constant-time compare | timing; invisible to clients |
| D13 | adapter `contains`, `starts_with` and `ends_with` put the value into a LIKE pattern as written, so `%` and `_` in user input act as wildcards (`%_` matches every row) | wildcards escaped; the value matches itself only | found while porting the Kysely adapter; affects any search built on these operators |
| D14 | a plugin's `schema` option (`mergeSchema`) writes renames into the plugin's shared default schema, so every later instance in the same process inherits them | each instance builds its own copy | observed while recording the schema fixtures; not wire-visible |
| D15 | rate limiting keys on the first `X-Forwarded-For` address and is skipped entirely when there is none (one warning, then unlimited) | the connection's address is used when the header is missing; unknown paths share one counter per client | a missing header must not switch limiting off; behind a proxy that sets the header both behave the same (`TestRateLimitMatchesLibrary`, `TestRateLimitIPv6Subnet`). Addresses are normalised as the library does (IPv6 to its /64, `Advanced.IPv6Subnet`). See "X-Forwarded-For is trusted" below |
| D16 | rate limiting is on only when `NODE_ENV=production` | on unless `RateLimit.Disabled` | Go has no development mode to infer it from |
| D17 | the rate limiter counts a request after its response, so simultaneous requests all pass the check before any is counted (30 parallel sign-ins: 30 attempts) | check and count in one step under a lock when the request arrives | the 3-per-10-seconds sign-in limit must hold under load (`TestRateLimitUnderConcurrency`); with a shared `RateLimitStore` the store must do the same atomically |
| D18 | callbackURL and Origin are matched by string: an upper-case host (`http://LOCALHOST:3000`) and `http://localhost:3000\@evil.com` are accepted, and a non-string callbackURL crashes with 500 | parsed and compared as origins: the upper-case host and the backslash form are refused (403), a non-string callbackURL is a 400 VALIDATION_ERROR | stricter, never looser; a browser sends canonical origins, so no real client is affected |

### X-Forwarded-For is trusted, as in the library

Both read the client address from the first `X-Forwarded-For` entry without checking where the request came from. Behind a proxy that sets the header that is right; a service that faces clients directly lets them choose their address, and with it their rate-limit bucket (rotating the header defeats the limit on both sides). Put the service behind a proxy that overwrites the header. D15 only covers a missing header; it does not make a spoofed one safe.

### Settings that cannot be zero

`Session.UpdateAge` and `EmailAndPassword.MinPasswordLength` treat zero as "use the default" (1 day, 8 characters), so "refresh on every request" and "no minimum" cannot be configured. Neither is needed by the first consumer; say so if it is.


### Notes on D9 as implemented

The default answer to a sign-up for a registered email is the library's own generic response (the one it gives when `autoSignIn` is off or email verification is required): the password is hashed anyway, and 200 `{"token":null,"user":{…synthetic…}}` comes back with no cookie and no new row. While `AutoSignIn` stays on, a real sign-up does return a token, so the missing token still hints that the address is taken; the response is only fully non-revealing together with `AutoSignIn: false`. `Compat.RevealExistingEmail` restores the library's default 422.

### Behaviour that differs only in how the handler is mounted

Mounted under an `http.ServeMux`, paths with `//` or `..` are redirected by the mux before the handler sees them, where the library answers 404. Serve `Auth.Handler()` directly on its prefix to get the library's 404s.
