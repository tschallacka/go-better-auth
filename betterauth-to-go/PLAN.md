# betterauth-to-go: plan

Status: DRAFT for Owner approval. Nothing is built until this is approved.
Written by hand: the planning skill's helper binaries are missing from release v2.0.0-alpha.9 (tschallacka/ai-skills#198).

## 1. Purpose

A temporary Go module that replaces the TypeScript library `better-auth` 1.6.14 (with `@better-auth/passkey` 1.6.14) for one application, Taskmanager, while that application moves its backend from Nuxt/Nitro to Go. It exists to aid the migration and is **removed when the transition is complete**.

During the overlap both implementations run against the same PostgreSQL tables and each must accept what the other wrote. Hard requirements: nobody is signed out, nobody resets a password, and the browser's `better-auth/client` calls keep working unchanged.

This is a different product from the general-purpose library described in `AGENTS.md` (argon2id, SQLite, own schema). Where they conflict, this plan follows the compatibility requirement: scrypt hashes in better-auth's format, Postgres only, the existing schema, no new columns or tables. Argon2id upgrade-on-login is out of scope until compatibility is proven.

Requested by the Taskmanager session ("Boss"); reference source is the public repo `github.com/tschallacka/Taskmanager` (commit bc68604) and the pinned npm tarballs (better-auth, @better-auth/passkey, @better-auth/core 1.6.14; @better-auth/utils 0.4.1; @noble/hashes 2.2.0; @noble/ciphers 2.2.0; better-call 1.3.5).

### 1.1 Independent library (Owner guidance, 2026-11-09)

This is an independent, reusable module for any project moving from better-auth to Go, not a Taskmanager component. Taskmanager is the first consumer and the first fixture, nothing more. Consequences:
- Its own `go.mod` and its own tags, importing nothing from Taskmanager or from the `go-better-auth` library in this repository.
- No application value is hard-coded. The issuer (`Taskmanager` in section 2), rpName, rpID, origins, provider list, session lifetimes, field names and every product rule come from `Config` and hooks. Section 2 describes the first consumer's configuration, not defaults.
- Everything better-auth makes configurable stays configurable here: the compatibility target is the 1.6.14 behaviour for any supported option, with Taskmanager's configuration as the tested reference set. Options not yet supported are rejected by `New` with a clear error, never silently ignored.
- Docs, tests and fixtures use neutral names; the Taskmanager-specific fixture lives in its own test directory.
- The module path and tag scheme in section 11 are provisional: github.com/tschallacka/go-better-auth/betterauth-to-go works for now, and the code must be movable to its own repository without changes other than the path.

### 1.2 Priority order (Owner guidance, 2026-11-09)

Compatibility with Taskmanager is good; security and reusability rank above it. When they conflict the order is: security, then reusability, then compatibility with the 1.6.14 wire behaviour. In practice:
- **Secure by default, compatibility by option.** Where the library's behaviour is a weakness, the default is the secure behaviour and an explicit `Compat` option in `Config` restores the library's behaviour for projects that need byte-for-byte parity during an overlap. This now covers D9 (the existing-email response on sign-up) and D11 (rate limits), which section 10 had kept as the library has them: D9 defaults to a non-revealing response with `Compat.RevealExistingEmail`, and D11 defaults to a pluggable `RateLimitStore` interface (memory default, shared store supplied by the project) instead of per-process counters only.
- **Existing data keeps working.** Verifying better-auth's scrypt hashes and decrypting its stored secrets is required for adoption, whatever the security preference. New hashes are written in the compatible format by default; an optional password-rehash-on-login (for example to argon2id) is a `Config` choice once compatibility is proven, never the default during an overlap.
- **Reusable by construction.** No global state, injectable clock, random source, HTTP client and logger, interfaces for the store and rate limiter, and no logging of secrets or tokens.
- A wire-visible secure default that breaks the first consumer is reported to its maintainer before it ships, and the maintainer can turn on the matching `Compat` flag; it does not weaken the default.

## 2. Scope

In (same paths, methods, request and response JSON, status codes and error codes as the library):
1. Core: email and password, sessions and cookies, sign-out, get-session, list and revoke sessions, change and reset password, email verification, update and delete user, accounts, origin and CSRF checks, rate limiting.
2. organization plugin (21 HTTP routes in the app's configuration), including generic additional fields on the organization (Taskmanager's `joinCode` is one such field, declared by the app with `input: false`; it is not part of better-auth) and the `allowUserToCreateOrganization` callback.
3. twoFactor (issuer `Taskmanager`), including backup codes and trusted devices.
4. passkey (WebAuthn, rpID = hostname of `BETTER_AUTH_URL`, rpName `Taskmanager`).
5. emailOTP (sign-in OTP, 600 s expiry, 3 attempts).
6. Discord, GitHub, Google and generic OAuth (`oidc`, discovery URL, PKCE), with an injectable HTTP client.
7. Additional fields, the library's generic mechanism: declared in `Config` per model (user, session, organization, member, invitation) with a type, `required`, `defaultValue` and `input: false` (returned to the client, never settable by it). Taskmanager's `isInstanceAdmin` and `canCreateOrganizations` (user) and `joinCode` (organization) are its declarations of this mechanism, used as test fixtures. Whether a plain member can read a field is a per-field setting.

### 2.1 Everything is in scope (Owner decision, 2026-11-09)

The target is the whole better-auth 1.6.14 feature set, not only what Taskmanager enables, delivered in phases so each phase is verified before the next starts:
- **Phase A (first consumer's set, section 8 steps 1 to 11):** core, organization, two-factor, passkey, emailOTP, Discord, GitHub, Google and generic OAuth, additional fields.
- **Phase B (user and session plugins):** admin (user roles, ban, impersonation, set-role, user management), username, anonymous, multi-session, bearer, custom-session, last-login-method.
- **Phase C (passwordless and extra factors):** magic-link, phone-number, one-time-token, one-tap, device-authorization, siwe, haveibeenpwned, captcha.
- **Phase D (token and provider plugins):** jwt, oidc-provider, mcp, oauth-proxy, open-api, and the remaining social providers.

The 1.6.14 package contains these plugins: access, additional-fields, admin, anonymous, bearer, captcha, custom-session, device-authorization, email-otp, generic-oauth, haveibeenpwned, jwt, last-login-method, magic-link, mcp, multi-session, oauth-proxy, oidc-provider, one-tap, one-time-token, open-api, organization, phone-number, siwe, two-factor, username. Every phase follows the same rule as phase A: research of the dist code, fixtures from the real library, a differential test per endpoint, and the section 1.2 priority order. Phase B to D research has not been done yet; each phase starts with its own research and `COMPAT.md` rows, and its own approval. `New` rejects configuration that enables a plugin from a phase not yet built.

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
  pgstore/           pgx implementation of Store (the only package importing pgx), plus CheckSchema
  migrations/        embedded SQL DDL in better-auth 1.6.14's table shapes, opt-in, never run automatically
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

### 5.1 Ease of adoption (Owner guidance, 2026-11-09)

The point of the module is to make the move from better-auth to Go easy for an existing code base, including its database migrations. Consequences for the design:
- **Drop-in surface.** Paths, cookies, JSON and error codes are the library's, so the browser client and existing middleware keep working; mounting is one `http.Handle("/api/auth/", a.Handler())` line plus a `ResolveSession` call in existing middleware. The README leads with a before/after of exactly that.
- **Migrations are shipped, not imposed.** The module never creates or alters tables on its own. It embeds (`embed.FS`) the DDL of the tables it uses, as plain SQL files in the exact shape better-auth 1.6.14 creates, for projects that want to apply them with their own tool (goose, migrate, atlas, Drizzle push, plain `psql`). A project that already has the tables (Taskmanager) applies nothing.
- **Schema check instead of schema ownership.** `pgstore.CheckSchema(ctx, pool)` compares the live tables and columns against what the module needs and returns a list of precise differences (missing column, wrong type, missing index) without changing anything. It is meant for startup and CI.
- **Additive only.** Any storage the tightened fixes would need is proposed to the schema owner as an exact additive shape first (Taskmanager's rule); until then those fixes use process memory, and the divergence is documented.
- **Bring your own pool, no global state.** `pgstore.New(*pgxpool.Pool)`; the `Store` interface lets a project adapt another database layer.
- **Documented migration path.** `README.md` includes a checklist: pin the secret and base URL to the TypeScript values, run both implementations side by side, compare with the differential harness, switch traffic, remove the TypeScript service, delete this module's compatibility-only code when the project later chooses its own formats.

## 6. Hooks

Mirror the library's semantics in Go extension points:
- Endpoint before and after hooks matched by path; they see the parsed body, headers and resolved session; they may abort with an API error (status, code, message), replace the request body (the app rewrites the email on `/sign-in/email`), or replace the returned JSON (organization member lists are scrubbed).
- Database hooks before and after for `user.create`, `user.update`, `session.create`; they may abort or return modified data.
- Request context exposes the path, headers and whether the call came through an OAuth `/callback/` route.
- Callbacks as function fields: `AllowUserToCreateOrganization`, `SendVerificationOTP(email, otp, type)`, `SendResetPassword`, `SendVerificationEmail`, `SendInvitationEmail`.

Tested against a fake application in this module's tests. The Taskmanager rules themselves are the application's job.

### 6.1 Events (Owner decision, 2026-11-09)

Events are notifications after the fact; hooks (above) can veto or modify, events cannot.
- One `Events` interface (a no-op base type to embed) and `WithEventHandler(h)`, which may be given several times; events are fanned out to every registered handler.
- Events are typed structs with a `context.Context`: session created and revoked, user created and updated, membership changed, password changed, two-factor enabled and disabled, passkey added and removed, sign-in failed.
- Handlers run synchronously after the database commit. A project wanting async work uses its own goroutine or queue inside its handler.
- A handler that panics or errors never fails the auth call; it is reported through the injected logger.
- No channels, no global registry.

### 6.2 Dynamic permission checks (Owner decision, 2026-11-09)

Beyond the static access-control statements and roles from `Config`, a project registers permission checks at runtime:
- `WithAuthorizer(name, func(ctx, Request) Decision)`, where `Request` carries the user, the active organization and the member's roles, the resource, the action, and the HTTP request context; `Decision` is `Allow`, `Deny` or `Abstain`.
- Evaluation: the default check (the static role statements) gives the baseline decision. Registered checks are overrides: when any of them returns `Allow` or `Deny`, that decision replaces the baseline in both directions (a check can grant what the baseline refuses and refuse what it grants). Among the registered checks `Deny` beats `Allow`, so one cautious check cannot be outvoted. If every check abstains, the baseline stands. Checks run in registration order and stop at the first `Deny`. A check that panics or errors counts as `Deny` (fail closed) and is logged.
- **Audit log of overrides.** Every permission decision produces an audit record with the permission (resource and action), the user id, the organization id, the baseline decision, the final decision, and whether it was changed by a registered check, naming the check. A record is written to an `AuditSink` interface (default: the injected logger; a project supplies its own sink to persist records, since this module adds no tables). Records never contain secrets, tokens or request bodies. Decisions that were not changed are logged at a low level or sampled (configurable) so the log stays useful.
- **Override counter.** For every (check name, permission) pair the module counts how often the check changed the baseline decision, readable through `Auth.AuditCounters()` and exposed to a project's metrics. Counters are in process memory, per instance, and reset on restart; a persistent count is the sink's job. This shows which overrides are used and which can be removed.
- The same mechanism backs every organization route's permission check and the has-permission endpoint, so the answer to "may this user do this" is one code path.
- Registration is by name so a check can be replaced or removed, and checks can be added after `New` before the handler starts serving.
- Default configuration reproduces the library's three built-in roles exactly; the differential tests pin the permission matrix against the real library with no authorizers registered.

## 7. Verification strategy

1. **Recorded vectors for pure functions** (`testdata/gen/*.mjs`): the real better-auth 1.6.14, its dependencies and Node's built-ins produce every expected value for hashing, encryption, signing, cookie parsing, JavaScript string behaviour, the schema (`getAuthTables`, the library's own DDL) and the database adapter's query results. Generated secrets and fake users only.
2. **Live differential harness** (`internal/difftest`, `testdata/gen/server.mjs`; amended 2026-11-12, replacing recorded request/response replays): a Go test starts the real library as a Node server on its own scratch database, sends it and the Go handler the same requests, and compares status, cookies, JSON bodies and resulting rows. Values that differ by nature (ids, tokens, timestamps) are masked by name in the test. A live run avoids replaying stale random values and lets one test drive both sides through the same flow; mail the library would send lands in an outbox the test reads.
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
- Everything else uses the standard library (`crypto/hmac`, `crypto/sha256`, `crypto/rand`, `encoding/*`, `net/http`).
- `golang.org/x/text/unicode/norm`: NFKC before scrypt. `x/crypto` has no normalisation, and without it a better-auth hash of a non-ASCII password (fullwidth or decomposed characters) does not verify; the crypto vector tests fail when it is removed. Decided in the foundation PR.

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
| D7 | Any organization member can read all invitations and roles, and every additional field of the organization | copy | restrict invitations and roles for plain members by default; additional fields readable by members unless the field is declared member-hidden |
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
