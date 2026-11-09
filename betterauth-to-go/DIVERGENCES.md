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
| D7 | any member reads all invitations, roles and joinCode | invitations and role reads restricted for plain members; joinCode stays readable by members (pending Owner confirmation, Taskmanager's team page shows it to every member) | Taskmanager does not rely on invitation or role reads |
| D8 | accept-invitation has no already-member check | checked in code, no schema change | duplicate member rows |
| D9 | sign-up returns 422 for an existing email (reveals the account) | non-revealing response by default; `Compat.RevealExistingEmail` restores the library behaviour | security and reusability rank above parity (PLAN.md 1.2); wire-visible, so Taskmanager is told before it ships |
| D11 | rate limits are per process, in memory | pluggable `RateLimitStore`, memory default, shared store supplied by the project | per-process counters are bypassed by running several instances; no schema change from this module |
| D10 | check-verification-otp distinguishes USER_NOT_FOUND from INVALID_OTP | one uniform error | account enumeration; Taskmanager does not call this endpoint |
| D12 | password hash compared with plain === | constant-time compare | timing; invisible to clients |
