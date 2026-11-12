# better-auth 1.6.14 core session flow (spec for task 4)

Research by the code-researcher agent, 2026-11-13, from /Users/mdibbets/git/better-auth-ref (v1.6.14) and the installed dist. S = packages/better-auth/src, C = packages/core/src, BC = node_modules/better-call/dist, U = node_modules/@better-auth/utils/dist. "~" = approximate line. Settle the gaps at the bottom against the live harness.

## 0. Order of one request
1. onRequest (S/api/index.ts:296-328): disabledPaths (404 text "Not Found"), plugin onRequest, rate-limit check.
2. basePath strip, then route; no match = 404.
3. body parse; disallowed media type = 415.
4. router middleware originCheckMiddleware.
5. before-hooks (S/api/to-auth-endpoints.ts:171).
6. zod validation of body and query (BC/context.mjs:11).
7. endpoint `use` middlewares (formCsrfMiddleware) (BC/context.mjs:84).
8. handler.
9. after-hooks (to-auth-endpoints.ts:297), run even when the handler threw an APIError (passed as `returned`).
10. response serialisation (:343).
11. onResponse: rate-limit counting (index.ts:331).

## 1. Request pipeline
- basePath = new URL(ctx.baseURL).pathname = "/api/auth" (S/api/index.ts:278; ctx.baseURL "http://localhost:3000/api/auth").
- Strip: pathname.split(basePath), drop first segment, join the rest (BC/router.mjs:31-35). Each of these gives 404, empty body, statusText "Not Found":
  - nothing left after stripping (:36)
  - `//` anywhere in the path
  - trailing-slash mismatch (skipTrailingSlashes false, index.ts:294)
  - no METHOD+path route (:44-52)
- Wrong method: same empty 404, not 405 (rou3 per method; inferred). OPTIONS and HEAD are not registered (404). No CORS in core.
- Body (BC/utils.mjs getBody):
  - request.body null: body undefined, no media check.
  - Router allows only application/json (index.ts:293); sign-in/email and sign-up/email also allow application/x-www-form-urlencoded (sign-up.ts:37; sign-in.ts ~411).
  - Disallowed type: 415 {"message":"Content-Type \"<raw>\" is not allowed. Allowed types: application/json","code":"UNSUPPORTED_MEDIA_TYPE"}.
  - Missing type with a body: message "Content-Type is required. Allowed types: …".
  - JSON match: /^application\/([a-z0-9.+-]*\+)?json/i. A form body becomes an object of strings.
- Error envelope:
  - Always {"message":…,"code":…} in that order (C/error/index.ts:26-34); codes and messages in C/error/codes.ts:16-70.
  - Content-Type application/json (BC/to-response.mjs:142). statusText is the string status (:114-118); whether it reaches the wire is unverified.
  - Set-Cookie set before a throw is kept (C/api/index.ts:22-33,105-113; to-auth-endpoints.ts:247-280).
  - zod failure: 400 {"message":"[body.<path>] <zod msg>; …","code":"VALIDATION_ERROR"}; exact zod 4.6.7 texts to capture live.
  - non-API exception: 500, empty body (BC/router.mjs:93-96).
- Success: JSON of the handler result. A raw null serialises as `null`, status 200, content-type json (to-response.mjs:123). Keys whose value is undefined are dropped.

## 2. Origin / CSRF
- originCheckMiddleware runs on every path (S/api/middlewares/origin-check.ts:59); returns early for GET/OPTIONS/HEAD or no request (:61-68).
- validateOrigin (:204-260):
  - Reads origin, else referer, else "" (:212).
  - Runs only if the request has a Cookie header (:213,229) unless forced.
  - Skipped when disableCSRFCheck or skipOriginCheck===true.
  - Missing origin or literal "null": 403 MISSING_OR_NULL_ORIGIN "Missing or null Origin" (:236).
  - Untrusted: 403 INVALID_ORIGIN "Invalid origin" (:259).
- Matching: pattern === getOrigin(url) for http/https (S/auth/trusted-origins.ts:43-46); a full Referer URL is reduced to its origin.
- Trusted origins: [new URL(baseURL).origin] plus options.trustedOrigins plus env BETTER_AUTH_TRUSTED_ORIGINS, comma-split (S/context/helpers.ts:136-157).
- Trap: skipOriginCheck defaults to true when NODE_ENV=test or env TEST is truthy (create-context.ts:383-387; C/env/env-impl.ts:60), which by backward compatibility also skips CSRF (origin-check.ts:14-19).
- URL fields, checked after validateOrigin and only when the check is not skipped (:76-130):
  - body/query callbackURL, body redirectTo, errorCallbackURL, newUserCallbackURL.
  - Relative paths allowed when they match ^\/(?!\/|\\|%2f|%5c)[\w\-.\+/@]*(?:\?[\w\-.\+/=&%@]*)?$ (trusted-origins.ts:18-27).
  - Failure: 403 INVALID_CALLBACK_URL "Invalid callbackURL", INVALID_REDIRECT_URL, and so on (:104-127).
- formCsrfMiddleware (sign-in/email and sign-up/email, after zod) (:286-327):
  - With cookies: validateOrigin.
  - Without cookies, reads Sec-Fetch-Site/Mode/Dest:
    - site "cross-site" with mode "navigate": 403 CROSS_SITE_NAVIGATION_LOGIN_BLOCKED (:311-321).
    - any other non-empty metadata: forced validateOrigin, which needs Origin or Referer (:326).
    - no metadata at all: no check.

## 3. Cookies
- Secure: advanced.useSecureCookies, else baseURL startsWith "https://", else isProduction (S/cookies/index.ts:60-69). For http://localhost:3000 there is no Secure flag and no __Secure- prefix, whatever NODE_ENV is.
- Names are "better-auth.<name>" (:90). Defaults: secure false, sameSite "lax", path "/", httpOnly true, no Domain unless crossSubDomain (:99-108).
- The cookies (:117-127):
  - session_token: maxAge 604800
  - session_data: maxAge 300, unused while cookieCache is off
  - account_data: unused
  - dont_remember: no maxAge
- Serialisation order: name=value; Max-Age=N; Domain=; Path=/; Expires=; HttpOnly; Secure; SameSite=Lax (BC/cookies.mjs:42-71). Max-Age is floored; above 34560000 throws.
- Signed value: encodeURIComponent(value + "." + base64std(HMAC-SHA256(secret, value))).
  - Read: %-decode, split at the last "."; signature not 44 chars ending "=" gives null; bad HMAC gives false.
- Chunking applies only to session_data and account_data above 4093 chars (.0, .1, …).
- Delete (S/cookies/index.ts:374-417): expireCookie drops earlier Set-Cookie entries for that name, then sets `name=` with the cookie's attributes and Max-Age=0.
- deleteSessionCookie, in order:
  1. session_token
  2. session_data
  3. Max-Age=0 for every request cookie whose name starts with "better-auth.session_data" (duplicates session_data if the client sent one; S/cookies/session-store.ts:38-52,188-204)
  4. dont_remember

## 4. Session
- Token: generateId(32), alphabet a-zA-Z0-9 (C/utils/id.ts:3-5), rejection sampling accepting bytes < 248 (U/random.mjs) (S/db/internal-adapter.ts:~358).
- Row ids: ctx.generateId({model}), also 32 alphanumeric (create-context.ts:235-248). Whether the kysely adapter uses it is inferred.
- Defaults (create-context.ts:293-302): expiresIn 604800 s, updateAge 86400 s, freshAge 86400 s.
- cookieCache is off when a database is set (:98-113).
- Session row (internal-adapter.ts:317-375):
  - ipAddress = getIp(headers) || "": the first valid IP in x-forwarded-for (S/utils/get-request-ip.ts:18-33); otherwise "127.0.0.1" in test/development, "" in production.
  - userAgent = header or "".
  - expiresAt = now+7d, or now+1d with dontRememberMe.
  - userId; createdAt = updatedAt = now.
- setSessionCookie (S/cookies/index.ts:268-310):
  - session_token Max-Age = expiresIn, omitted when dontRememberMe.
  - With dontRememberMe also signed better-auth.dont_remember=true.<sig>, no Max-Age.
  - An explicit false does not clear an existing dont_remember cookie.
- GET /get-session (S/api/routes/session.ts):
  - Methods GET and POST (:35). POST without deferSessionRefresh: 405 METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED (:78-83).
  - Missing cookie, bad signature or bad format: 200 `null`, no Set-Cookie (:86-93).
  - Session not found or expired: deleteSessionCookie, DB delete of an expired row, 200 `null` (:367-385).
  - Valid dont_remember cookie, or query disableRefresh: no refresh (:389-402). z.coerce.boolean makes ?disableRefresh=false also true (session-store.ts:298-317).
  - Refresh when expiresAt - expiresIn*1000 + updateAge*1000 <= now (:414-428).
  - Refresh does (:447-490):
    - DB update expiresAt=now+7d, updatedAt=now.
    - Set-Cookie session_token with Max-Age=floor((expiresAt-Date.now())/1000), usually 604799.
    - No dont_remember cookie.
    - If the update returns null: delete cookies, 401 FAILED_TO_GET_SESSION.
  - Response {"session":{row},"user":{row}}; nothing filtered by default; key order is the adapter row's; dates are ISO with ms and Z.
  - Non-API exception: 500 FAILED_TO_GET_SESSION (:509-517).

## 5. POST /sign-up/email (S/api/routes/sign-up.ts)
- zod (:16-25): name string (required, "" allowed), email z.email(), password non-empty string, image?, callbackURL?, rememberMe? (boolean; a form "false" fails zod); .and(record) lets extra keys through.
  - A bad email fails at zod with VALIDATION_ERROR; the handler's INVALID_EMAIL cannot be reached over HTTP.
- Handler order:
  1. disabled: 400 EMAIL_PASSWORD_SIGN_UP_DISABLED "Email and password sign up is not enabled" (:184-191)
  2. INVALID_EMAIL (:211), INVALID_PASSWORD (:215)
  3. length < 8: 400 PASSWORD_TOO_SHORT "Password too short" (:220-225)
  4. length > 128: 400 PASSWORD_TOO_LONG (:229-234). Lengths count UTF-16 units.
  5. email lowercased and looked up (:247-248)
- Existing email: 422 {"message":"User already exists. Use another email.","code":"USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"} (:319-324); no dummy hash. (D9: Go defaults to non-revealing.)
- Otherwise:
  - Hash the password.
  - User row: email lowercased, name, image if given, extra fields, emailVerified false, createdAt = updatedAt = now (:336-342; internal-adapter.ts:148-165).
  - Account row: providerId "credential", accountId = user.id, userId, password = hash, createdAt = updatedAt = now, other columns null (:368-373; internal-adapter.ts:960-973).
  - Runs inside runWithTransaction (:181); whether that is a real transaction is unverified.
- No verification email by default (:374-376).
- autoSignIn defaults on (:235-240); session created with rememberMe===false (:413-430).
- Response 200 {"token":"<32>","user":{…}} (:431-437). Cookies: session_token, plus dont_remember when rememberMe is false.

## 6. POST /sign-in/email (S/api/routes/sign-in.ts)
- zod: email string, password string, callbackURL?, rememberMe? (default true) (:369-404). Form or JSON body.
- Order:
  1. disabled: 400 EMAIL_PASSWORD_DISABLED "Email and password is not enabled" (:474-480)
  2. z.email() fails: 400 INVALID_EMAIL "Invalid email" (:483-486)
  3. lookup by email.toLowerCase() with accounts joined (:487; internal-adapter.ts:921-945)
- No user, no credential account or no password: hash the submitted password (timing), then 401 {"message":"Invalid email or password","code":"INVALID_EMAIL_OR_PASSWORD"} (:490-519).
- Wrong password: same 401 (:522-532).
- createSession(rememberMe===false); failure 401 FAILED_TO_CREATE_SESSION (:568-578); then setSessionCookie.
- callbackURL set: a Location header is added, status stays 200 (:590-592).
- Response {"redirect":<bool>,"token":…,"url":<callbackURL>,"user":{…}}; url omitted when undefined (:594-602).

## 7. POST /sign-out (S/api/routes/sign-out.ts)
- No body schema; a body without Content-Type gives 415.
- Valid signed token: delete the session by token; errors are only logged (:35-45).
- Always deleteSessionCookie.
- Response 200 {"success":true}. The origin check applies only when a Cookie header is present.

## 8. Rate limiting (S/api/rate-limiter/index.ts; create-context.ts:340-347)
- enabled = options.rateLimit.enabled ?? isProduction. Window 10 s, max 100, in memory.
- IP: the first valid x-forwarded-for entry. In production with no IP the limit is skipped with a one-time warning (~171-182).
- Key `${ip}|${normalizedPath}`, trailing slashes stripped (C/utils/ip.ts:206-210; C/utils/url.ts:17-25).
- Special rules (~300): /sign-in*, /sign-up*, /change-password*, /change-email* get window 10 and max 3.
- Blocked when now - lastRequest < window*1000 && count >= max, so the 4th sign-in inside 10 s is blocked.
- Counted in onResponse for every response, 404s included. After more than a window, the count resets to 1; otherwise it increments and lastRequest = now.
- 429: body {"message":"Too many requests. Please try again later."}, header X-Retry-After = ceil((lastRequest+window-now)/1000), no content-type set (text/plain;charset=UTF-8 from Fetch, inferred).

## 9. Hooks
- Endpoint hooks: user hooks.before, then plugin before-hooks (~516-563). They run after the origin middleware and before zod. A non-context return short-circuits the endpoint (:200-212). After-hooks run even after an APIError.
- DB hooks (S/db/with-hooks.ts): create.before can veto with false or merge data (:41-66). create.after and update.after are queued after the transaction (:80-97,156-173). They fire on:
  - user.create (sign-up)
  - account.create
  - session.create (sign-up, sign-in)
  - session.update (get-session refresh)
  - session.delete (sign-out, expired get-session)

## Gaps, settled against the live library (2026-11-13)
1. zod messages: `[body.<field>] Invalid input: expected <type>, received <type>` and `[body.email] Invalid email address`, joined with "; " in schema order (sign-up: name, email, password). The sign-up intersection with z.record adds `[body] Invalid input: expected record, received <type>` when the body is not an object. Pinned by `compat_test/core_test.go`.
2. A wrong method on a known path is the same empty 404 as an unknown path.
3. The reason phrase is the standard one ("415 Unsupported Media Type"); Go's net/http writes the same.
4. Row key order is the schema's field order with `id` last; the Go side writes JSON in that order (`object` in errors.go) and the differential test compares key order.
5. Not settled: whether `runWithTransaction` opens a real transaction on PostgreSQL. The Go side does (sign-up writes user and account in one transaction).

Observed beyond the spec: a request without Content-Type is not 415 but an undefined body (a VALIDATION_ERROR on endpoints with a body schema); malformed JSON is an empty 500; in production without X-Forwarded-For the session's ipAddress is "".
