# betterauth-to-go: plan

Status: DRAFT for Owner approval. Nothing is built until this is approved.
Written by hand: the planning skill's helper binaries are missing from release v2.0.0-alpha.9 (tschallacka/ai-skills#198).

## 1. Purpose

A temporary Go module that replaces the TypeScript library `better-auth` 1.6.14 (with `@better-auth/passkey` 1.6.14) for one application, Taskmanager, while that application moves its backend from Nuxt/Nitro to Go. It exists to aid the migration and is **removed when the transition is complete**.

During the overlap both implementations run against the same PostgreSQL tables and each must accept what the other wrote. Hard requirements: nobody is signed out, nobody resets a password, and the browser's `better-auth/client` calls keep working unchanged.

This is a different product from the general-purpose library described in `AGENTS.md` (argon2id, SQLite, own schema). Where they conflict, this plan follows the compatibility requirement: scrypt hashes in better-auth's format, Postgres only, the existing schema, no new columns or tables. Argon2id upgrade-on-login is out of scope until compatibility is proven.

Requested by the Taskmanager session ("Boss"); reference source is the public repo `github.com/tschallacka/Taskmanager` (commit bc68604) and the pinned npm tarballs (better-auth, @better-auth/passkey, @better-auth/core 1.6.14; @better-auth/utils 0.4.1; @noble/hashes 2.2.0; @noble/ciphers 2.2.0; better-call 1.3.5).

## 2. Scope

In (same paths, methods, request and response JSON, status codes and error codes as the library):
1. Core: email and password, sessions and cookies, sign-out, get-session, list and revoke sessions, change and reset password, email verification, update and delete user, accounts, origin and CSRF checks, rate limiting.
2. organization plugin (21 HTTP routes in the app's configuration), including the server-issued `joinCode` field and the `allowUserToCreateOrganization` callback.
3. twoFactor (issuer `Taskmanager`), including backup codes and trusted devices.
4. passkey (WebAuthn, rpID = hostname of `BETTER_AUTH_URL`, rpName `Taskmanager`).
5. emailOTP (sign-in OTP, 600 s expiry, 3 attempts).
6. Discord, GitHub, Google and generic OAuth (`oidc`, discovery URL, PKCE), with an injectable HTTP client.
7. User additional fields `isInstanceAdmin` and `canCreateOrganizations` (output only).

Out: sending mail (callbacks), the application's business rules (the app implements them through hooks), any server or router beyond an `http.Handler`.

## 3. Compatibility facts confirmed against the source

Checked directly in the published tarballs, not only in research notes:
- **Password hash**: `saltHex:keyHex`; salt is 16 random bytes rendered as 32 hex characters and then used as the *text* of the salt (UTF-8 bytes of the hex string); key = `scrypt(NFKC(password), salt, N=16384, r=16, p=1, dkLen=64)`; key rendered as hex. Verification compares the hex string.
- **Symmetric encryption** (two-factor secrets, backup codes): key = SHA-256 of the auth secret; XChaCha20-Poly1305 with a random 24-byte nonce prepended to the ciphertext and tag; the whole thing hex encoded. An optional `$ba$<version>$` envelope exists for versioned secrets; bare hex is used when a plain string secret is configured.
- **Cookie signature**: HMAC-SHA256 over the value, standard base64, appended as `value.signature`, then URL-encoded.

Unconfirmed items are tracked in section 9 and in `QUESTIONS.md` once created.

## 4. Package layout

Module path: `betterauth-to-go` placeholder, to be confirmed by Owner (see section 9).

```
betterauth-to-go/
  go.mod
  README.md, COMPAT.md, DIVERGENCES.md, QUESTIONS.md
  auth.go            Auth, New, Config, Option, Handler, ResolveSession
  store.go           Store interface and row types
  pgstore/           pgx implementation of Store (the only package importing pgx)
  internal/crypto/   scrypt password, XChaCha20-Poly1305, HMAC cookie signing, id and token generation
  internal/cookie/   cookie names, signing, parsing, attributes
  internal/session/  session lookup, refresh, creation, revocation
  internal/api/      endpoint dispatcher, error envelope, origin check, rate limiter
  internal/core/     email and password, verification, accounts
  internal/org/      organization plugin
  internal/twofactor/
  internal/passkey/  uses go-webauthn
  internal/emailotp/
  internal/oauth/    state, PKCE, providers, generic OIDC
  hooks.go           endpoint hooks, database hooks, request context, callbacks, events
  testdata/gen/      Node or Bun fixture generator driving the real better-auth
  testdata/fixtures/ recorded DB dumps and request/response pairs (generated, no real data)
  compat_test/       differential harness
```

## 5. Public interface (as requested by Boss)

```go
type Store interface { /* DB access over the shared tables; no global state */ }
func New(cfg Config, store Store, opts ...Option) (*Auth, error)
func (a *Auth) Handler() http.Handler                              // /api/auth/*, strip-prefix aware
func (a *Auth) ResolveSession(r *http.Request) (*SessionInfo, error) // ErrNoSession when none, expired or revoked
```

`pgstore.New(*pgxpool.Pool) Store` is the production implementation. Tests use it against scratch databases and a fake `Store` for unit tests. No Taskmanager code is imported.

`ResolveSession` does one indexed query (session by token joined to user), allocates little, adds no cache, and has a benchmark with a target under 100 microseconds CPU excluding the database round trip.

Events (optional callbacks): `OnSessionRevoked(userID, sessionID)`, `OnMembershipChanged(orgID, userID)`, `OnPasswordChanged(userID)`.

## 6. Hooks

Mirror the library's semantics in Go extension points:
- Endpoint before and after hooks matched by path; they see the parsed body, headers and resolved session; they may abort with an API error (status, code, message), replace the request body (the app rewrites the email on `/sign-in/email`), or replace the returned JSON (organization member lists are scrubbed).
- Database hooks before and after for `user.create`, `user.update`, `session.create`; they may abort or return modified data.
- Request context exposes the path, headers and whether the call came through an OAuth `/callback/` route.
- Callbacks as function fields: `AllowUserToCreateOrganization`, `SendVerificationOTP(email, otp, type)`, `SendResetPassword`, `SendVerificationEmail`, `SendInvitationEmail`.

Tested against a fake application in this module's tests. The Taskmanager rules themselves are the application's job.

## 7. Verification strategy

1. **Fixture generator** (`testdata/gen/`, Node or Bun): starts the real better-auth 1.6.14 with the app's configuration against a scratch PostgreSQL database and drives every flow, recording DB dumps and request/response pairs. Generated secrets and fake users only.
2. **Differential harness** (Go): replays each recorded request against `Handler()` on the same data and diffs status, cookies and JSON bodies. Ignored fields are ids, timestamps and random tokens, listed in the test.
3. **Cross-compatibility both ways, automated in CI**: (a) data written by better-auth is read by this module (old hash sign-in, old cookie, old TOTP secret, old passkey); (b) data written by this module is read by the real library (password sign-in, cookie, TOTP).
4. **Security tests kept permanently**: tampered or truncated cookie, bad signature, expired and revoked session, replayed OTP, session fixation on sign-in, CSRF and origin checks, OAuth state and PKCE mismatch, open redirect on callback, passkey origin and rpID mismatch, backup-code reuse, rate limits, constant-time comparisons where the library has them, no secrets in logs or errors.
5. `go vet`, `staticcheck`, `go test -race ./...` clean; fuzz targets for the cookie and token parsers; a `ResolveSession` benchmark.

An endpoint is not marked done in `COMPAT.md` until its recorded-request differential test passes against the real library.

## 8. Order of work (each step reported to Boss with a table of what passes)

1. `COMPAT.md` listing every endpoint (this plan's companion).
2. Fixture generator.
3. Cookie, `ResolveSession`, sign-in, sign-out, get-session with password.
4. Hooks and database hooks.
5. organization plugin.
6. twoFactor.
7. passkey.
8. emailOTP.
9. Social and OIDC.
10. Remaining core flows (reset, verify, change password).
11. Security tests, fuzz, benchmark, cross-compatibility in CI.

Each step is its own PR. Work is split into atomic units per goal and handed out as: research and testing by Haiku agents, implementation and review by the stronger model, every PR reviewed by a second agent before it reaches the Owner.

## 9. Dependencies (each justified)

- `github.com/jackc/pgx/v5`: the application already uses `*pgxpool.Pool`; `database/sql` would force a second pool and lose pgx types.
- `github.com/go-webauthn/webauthn`: required by the brief; implementing attestation and assertion verification by hand would be a security risk.
- `golang.org/x/crypto`: `scrypt`, `chacha20poly1305` (XChaCha20-Poly1305). Standard library has neither.
- Everything else uses the standard library (`crypto/hmac`, `crypto/sha256`, `crypto/rand`, `encoding/*`, `net/http`, `golang.org/x/text/unicode/norm` for NFKC if not in `x/crypto`; this one needs a decision).

No OAuth2 or OIDC library: the TypeScript flow is small and must match byte for byte; a library's different defaults would be a divergence risk.

## 10. Decisions needed from the Owner

The library has behaviours that are weaknesses. The default is to copy them exactly (Boss's rule) and list each in `DIVERGENCES.md`. Please confirm or choose to tighten:

| # | Library behaviour | Default | Option |
|---|---|---|---|
| D1 | Google and generic OIDC decode the `id_token` without verifying its signature | copy | verify via JWKS |
| D2 | Generic OIDC explicit link route skips the trusted-provider and verified-email check | copy | apply the check |
| D3 | Generic OIDC `iss` check is optional | copy | require it |
| D4 | TOTP codes have no replay tracking | copy | reject reuse within the window (the brief asks for a replay test) |
| D5 | An expired two-factor cookie may work once | copy | reject expired |
| D6 | Enabling two-factor for an already-verified user regenerates the secret with the password only | copy | require current TOTP |
| D7 | Any organization member can read all invitations, roles and `joinCode` | copy | restrict |
| D8 | Accepting an invitation has no already-member check; no unique index on member(org,user) | copy | check in code (no schema change) |
| D9 | Sign-up returns 422 for an existing email, revealing the account | copy | n/a, client depends on it |
| D10 | emailOTP check endpoint distinguishes USER_NOT_FOUND from INVALID_OTP | copy | uniform error |
| D11 | Rate limits are per process and memory only; two implementations count separately during the overlap | copy | shared store needs schema change, so no |
| D12 | Password verify uses plain `===` | use constant-time compare (not observable by the client) | copy |

Any tightening changes wire behaviour and must be agreed with Boss because the TypeScript client parses these responses. D12 is the one deviation proposed by default.

## 11. Open questions and risks

- Module path and where the module lives (this plan sits in a `betterauth-to-go/` subdirectory of `go-better-auth` on a branch because no new repository could be created).
- NFKC normalisation: confirm whether `golang.org/x/text/unicode/norm` is acceptable as an extra dependency, or whether `x/crypto` is enough.
- Behaviours described in the research notes that were read but not executed (first-user race, `set-password` having no HTTP path, TOTP and 2FA cookie edge cases). The fixture generator will settle each against the real library; results go to `QUESTIONS.md`.
- Rate limiting is enabled in the library only in production, in memory, keyed by IP and path; reproducing the exact buckets and IP source (`X-Forwarded-For`) is required by the brief.
- The research was gathered by Haiku agents reading the dist code. Every claim that a Go implementation relies on is re-verified by a differential test before the endpoint is marked done.
