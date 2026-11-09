# Compatibility table: better-auth 1.6.14 HTTP endpoints (planned)

Draft inventory compiled by a Haiku agent from research reports; not yet verified endpoint by endpoint against the dist source. A row stays "planned" until its recorded-request differential test passes against the real library. Paths are relative to /api/auth.

| Method | Path (relative to /api/auth) | Plugin | Success response | Notable error codes | Deviation/risk note | Status | Differential test |
|---|---|---|---|---|---|---|---|
| POST | /sign-up/email | core | 200 {token or null, user} | EMAIL_PASSWORD_SIGN_UP_DISABLED, INVALID_EMAIL, INVALID_PASSWORD, PASSWORD_TOO_SHORT, PASSWORD_TOO_LONG, USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL (422), FAILED_TO_CREATE_USER, FAILED_TO_CREATE_SESSION | Existing email returns 422 in default config, which reveals account existence | planned | TBD |
| POST | /sign-in/email | core | 200 {redirect, token, url, user}; 2FA accounts get {twoFactorRedirect, twoFactorMethods} instead | EMAIL_PASSWORD_DISABLED, INVALID_EMAIL, INVALID_EMAIL_OR_PASSWORD (401), EMAIL_NOT_VERIFIED (403), FAILED_TO_CREATE_SESSION | EMAIL_NOT_VERIFIED is reached only after a correct password | planned | TBD |
| POST | /sign-out | core | 200 {success:true} | none listed | - | planned | TBD |
| GET or POST | /get-session | core | 200 {session, user} or null | 405 METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED (POST without deferSessionRefresh), 500 FAILED_TO_GET_SESSION | Session token is returned in the response body | planned | TBD |
| GET | /list-sessions | core | 200 array of sessions | UNAUTHORIZED (401) | - | planned | TBD |
| POST | /revoke-session | core | 200 {status:true} | INTERNAL_SERVER_ERROR (500) | Always 200 whether or not the session is owned, so no leak | planned | TBD |
| POST | /revoke-sessions | core | 200 {status:true} | none listed | Current session cookie is not expired here; it is cleared on the next get-session | planned | TBD |
| POST | /revoke-other-sessions | core | 200 {status:true} | none listed | - | planned | TBD |
| POST | /request-password-reset | core | 200 {status:true, message} (same for unknown email) | RESET_PASSWORD_DISABLED (400), INVALID_CALLBACK_URL (403) | Response timing can differ for known and unknown email unless the send is backgrounded (inferred) | planned | TBD |
| GET | /reset-password/:token | core | 302 to callbackURL with token query | 302 to callbackURL with error=INVALID_TOKEN | - | planned | TBD |
| POST | /reset-password | core | 200 {status:true} | INVALID_TOKEN (400), PASSWORD_TOO_SHORT (400), PASSWORD_TOO_LONG (400) | Length checks run before the token check, so a bad token with a short password returns a length error | planned | TBD |
| POST | /change-password | core | 200 {token or null, user} | PASSWORD_TOO_SHORT, PASSWORD_TOO_LONG, CREDENTIAL_ACCOUNT_NOT_FOUND, INVALID_PASSWORD (400), FAILED_TO_GET_SESSION (500) | revokeOtherSessions leaves some cookies until the next get-session | planned | TBD |
| POST | /verify-password | core | 200 {status:true} | INVALID_PASSWORD (400) | HTTP exposure unconfirmed (metadata scope server) | planned | TBD |
| POST | /send-verification-email | core | 200 {status:true} (same for unknown or verified email without session) | VERIFICATION_EMAIL_NOT_ENABLED, EMAIL_MISMATCH, EMAIL_ALREADY_VERIFIED (400) | - | planned | TBD |
| GET | /verify-email | core | 200 {status:true, user:null} or 302 to callbackURL | TOKEN_EXPIRED, INVALID_TOKEN, USER_NOT_FOUND, INVALID_USER | Email link is a stateless HS256 JWT with no single-use record, so it is replayable until exp | planned | TBD |
| POST | /change-email | core | 200 {status:true} (same for an existing address) | CHANGE_EMAIL_DISABLED (400), Email is the same (400, no code), Verification email isn't enabled (400, no code) | - | planned | TBD |
| POST | /update-user | core | 200 {status:true} | EMAIL_CAN_NOT_BE_UPDATED (400), No fields to update (400) | - | planned | TBD |
| POST | /delete-user | core | 200 {success:true, message} | NOT_FOUND (404, when disabled), CREDENTIAL_ACCOUNT_NOT_FOUND, INVALID_PASSWORD (400), SESSION_EXPIRED (400) | - | planned | TBD |
| GET | /delete-user/callback | core | 302 to callbackURL or 200 {success:true, message} | NOT_FOUND (404), FAILED_TO_GET_USER_INFO (404), INVALID_TOKEN (404) | - | planned | TBD |
| GET | /list-accounts | core | 200 array of accounts without tokens, with scopes | UNAUTHORIZED (401, via sessionMiddleware) | - | planned | TBD |
| POST | /link-social | core | 200 {url, status:true, redirect} | PROVIDER_NOT_FOUND, ID_TOKEN_NOT_SUPPORTED (404), INVALID_TOKEN, FAILED_TO_GET_USER_INFO, USER_EMAIL_NOT_FOUND, LINKING_NOT_ALLOWED, LINKING_DIFFERENT_EMAILS_NOT_ALLOWED (401), LINKING_FAILED (417) | Trust and email checks not traced in linkSocialAccount; may differ from the callback path | planned | TBD |
| POST | /unlink-account | core | 200 {status:true} | FAILED_TO_UNLINK_LAST_ACCOUNT, ACCOUNT_NOT_FOUND (400) | - | planned | TBD |
| POST | /get-access-token | core | 200 {accessToken, accessTokenExpiresAt, scopes, idToken} | UNAUTHORIZED (401), PROVIDER_NOT_SUPPORTED, ACCOUNT_NOT_FOUND, FAILED_TO_GET_ACCESS_TOKEN (400) | OAuth access tokens stored in plain text (encryptOAuthTokens unset) | planned | TBD |
| POST | /refresh-token | core | not stated in report | PROVIDER_NOT_SUPPORTED, TOKEN_REFRESH_NOT_SUPPORTED, ACCOUNT_NOT_FOUND, REFRESH_TOKEN_NOT_FOUND, FAILED_TO_REFRESH_ACCESS_TOKEN (400) | - | planned | TBD |
| GET | /account-info | core | not analysed in report | not analysed in report | Not analysed in report | planned | TBD |
| GET | /ok | core | 200 {ok:true} | none | - | planned | TBD |
| GET | /error | core | HTML error page | none | - | planned | TBD |
| POST | /organization/create | organization | 200 organization with members | YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION (403), ORGANIZATION_ALREADY_EXISTS (400), FORBIDDEN (403, crew hook), UNAUTHORIZED (401) | - | planned | TBD |
| POST | /organization/check-slug | organization | 200 {status:true} | ORGANIZATION_SLUG_ALREADY_TAKEN (400), UNAUTHORIZED (401) | - | planned | TBD |
| POST | /organization/update | organization | 200 updated organization | ORGANIZATION_NOT_FOUND, USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION (400), YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION (403), ORGANIZATION_SLUG_ALREADY_TAKEN (400) | - | planned | TBD |
| POST | /organization/delete | organization | 200 deleted organization | YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION (403), ORGANIZATION_DELETION_DISABLED (404), USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION (400), UNAUTHORIZED (401) | Other members' sessions keep the deleted organization as their active id | planned | TBD |
| GET | /organization/get-full-organization | organization | 200 organization with members and invitations; null when no active organization | ORGANIZATION_NOT_FOUND (400), USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION (403), UNAUTHORIZED (401) | Invitation emails returned for every status; joinCode returned to all members | planned | TBD |
| POST | /organization/set-active | organization | 200 organization, or null when clearing | ORGANIZATION_NOT_FOUND (400), USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION (403), UNAUTHORIZED (401) | joinCode returned to all members | planned | TBD |
| GET | /organization/list | organization | 200 array of organizations | UNAUTHORIZED (401) | joinCode returned to all members | planned | TBD |
| POST | /organization/has-permission | organization | 200 {error:null, success} | NO_ACTIVE_ORGANIZATION (400), USER_IS_NOT_A_MEMBER_OF_THIS_ORGANIZATION (401), UNAUTHORIZED (401) | - | planned | TBD |
| POST | /organization/invite-member | organization | 200 invitation row | INVALID_EMAIL, MEMBER_NOT_FOUND, ORGANIZATION_NOT_FOUND, ROLE_NOT_FOUND, USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION, USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION (400), YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION, YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE, INVITATION_LIMIT_REACHED (403), UNAUTHORIZED (401) | No invitation email is sent (sendInvitationEmail unset) | planned | TBD |
| POST | /organization/cancel-invitation | organization | 200 updated invitation | INVITATION_NOT_FOUND, MEMBER_NOT_FOUND, ORGANIZATION_NOT_FOUND (400), YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION (403) | No status check, so accepted or rejected invitations can be set to canceled | planned | TBD |
| POST | /organization/accept-invitation | organization | 200 {invitation, member} | INVITATION_NOT_FOUND, ORGANIZATION_NOT_FOUND (400), YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION, ORGANIZATION_MEMBERSHIP_LIMIT_REACHED, FORBIDDEN (403) | No membership check, so a repeat accept creates a duplicate member row | planned | TBD |
| POST | /organization/reject-invitation | organization | 200 {invitation, member:null} | INVITATION_NOT_FOUND, ORGANIZATION_NOT_FOUND (400), YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION (403) | No expiry check, so an expired invitation can still be rejected | planned | TBD |
| GET | /organization/get-invitation | organization | 200 invitation with organization name, slug and inviterEmail | Invitation not found! (400, no code), INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION, ORGANIZATION_NOT_FOUND (400), YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION (403), Not authenticated (401, no code) | Reveals the inviter's email to the recipient | planned | TBD |
| GET | /organization/list-invitations | organization | 200 array of all invitations for the organization | Organization ID is required (400), You are not a member of this organization (403), Not authenticated (401, no code) | Any member can read every invitation email | planned | TBD |
| GET | /organization/list-user-invitations | organization | 200 pending invitations for the email, with organization name | EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION (403), User email cannot be passed for client side API calls (400), Missing session headers, or email query parameter (400) | Requires a verified email unconditionally; expired invitations are not filtered | planned | TBD |
| POST | /organization/remove-member | organization | 200 {member} | NO_ACTIVE_ORGANIZATION, MEMBER_NOT_FOUND, YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER, ORGANIZATION_NOT_FOUND (400), YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER (401) | Owner check runs before the permission check; the owner error text is misleading | planned | TBD |
| POST | /organization/update-member-role | organization | 200 updated member row | BAD_REQUEST, NO_ACTIVE_ORGANIZATION, MEMBER_NOT_FOUND, YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER, ORGANIZATION_NOT_FOUND (400), YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER (403) | Role is not validated, so arbitrary role strings are stored | planned | TBD |
| GET | /organization/get-active-member | organization | 200 member with user | NO_ACTIVE_ORGANIZATION, MEMBER_NOT_FOUND (400) | - | planned | TBD |
| POST | /organization/leave | organization | 200 removed member row | MEMBER_NOT_FOUND, YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER (400), UNAUTHORIZED (401) | - | planned | TBD |
| GET | /organization/list-members | organization | 200 {members, total} | ORGANIZATION_NOT_FOUND, NO_ACTIVE_ORGANIZATION (400), YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION (403) | - | planned | TBD |
| GET | /organization/get-active-member-role | organization | 200 {role} | ORGANIZATION_NOT_FOUND, NO_ACTIVE_ORGANIZATION (400), YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION (403) | Any member can read any other member's role | planned | TBD |
| POST | /two-factor/enable | two-factor | 200 {totpURI, backupCodes} | INVALID_PASSWORD (400), UNAUTHORIZED (401) | Re-enabling a verified user replaces the secret with no code check; password is the only gate; old backup codes invalidated; delete then create is not atomic | planned | TBD |
| POST | /two-factor/disable | two-factor | 200 {status:true} | INVALID_PASSWORD (400), UNAUTHORIZED (401), FORBIDDEN (403, extra-addresses hook) | Other sessions are not revoked | planned | TBD |
| POST | /two-factor/get-totp-uri | two-factor | 200 {totpURI} with decrypted secret | TOTP_NOT_ENABLED, INVALID_PASSWORD (400) | Returns the decrypted TOTP secret; does not check verified | planned | TBD |
| POST | /two-factor/verify-totp | two-factor | 200 {token, user} | INVALID_TWO_FACTOR_COOKIE (401), INVALID_CODE (401), TOTP_NOT_ENABLED (400) | No TOTP replay protection and no attempt counter; code accepted for about 90 s; 2FA cookie expiry not checked on verify | planned | TBD |
| POST | /two-factor/send-otp | two-factor | 200 {status:true} when configured; not reachable in app | OTP_NOT_CONFIGURED (400, returned before auth check) | Always 400 in app (sendOTP unset) | planned | TBD |
| POST | /two-factor/verify-otp | two-factor | 200 {token, user} | INVALID_TWO_FACTOR_COOKIE (401), OTP_HAS_EXPIRED, TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE (400), INVALID_CODE (401) | In app always 400 OTP_HAS_EXPIRED; session-mode record not deleted, so a code can be replayed within 3 min | planned | TBD |
| POST | /two-factor/verify-backup-code | two-factor | 200 {token, user} | INVALID_TWO_FACTOR_COOKIE (401), BACKUP_CODES_NOT_ENABLED (400), INVALID_BACKUP_CODE (401), CONFLICT (409) | OpenAPI text says {user, session} but code returns token; disableSession path does not consume the 2FA cookie | planned | TBD |
| POST | /two-factor/generate-backup-codes | two-factor | 200 {status:true, backupCodes} | TWO_FACTOR_NOT_ENABLED, INVALID_PASSWORD (400) | - | planned | TBD |
| POST | /email-otp/send-verification-otp | email-otp | 200 {success:true} (same for any email) | INVALID_EMAIL (400), Invalid OTP type (400, no code), zod enum error (400) | Only the sign-in type is mailed; other types are stored and never sent | planned | TBD |
| POST | /email-otp/check-verification-otp | email-otp | 200 {success:true}; OTP not consumed | USER_NOT_FOUND, INVALID_OTP, OTP_EXPIRED, INVALID_EMAIL (400), TOO_MANY_ATTEMPTS (403) | USER_NOT_FOUND reveals whether an account exists; rate limit 3 per 60 s per IP | planned | TBD |
| POST | /email-otp/verify-email | email-otp | 200 {status:true, token or null, user} | INVALID_OTP, OTP_EXPIRED, USER_NOT_FOUND (400), TOO_MANY_ATTEMPTS (403) | Effectively unusable in app because email-verification OTPs are never mailed | planned | TBD |
| POST | /sign-in/email-otp | email-otp | 200 {token, user} | FORBIDDEN (403, extra addresses, 2FA or sign-up closed), INVALID_OTP, OTP_EXPIRED (400), TOO_MANY_ATTEMPTS (403), That address cannot be used (400), That address is already in use (400) | 403 for 2FA accounts reveals the account has 2FA; rememberMe not honoured; concurrent correct codes may both succeed (uncertain) | planned | TBD |
| POST | /email-otp/request-password-reset | email-otp | 200 {success:true} for any email | none listed | Nothing is mailed in app (forget-password type not sent) | planned | TBD |
| POST | /forget-password/email-otp | email-otp | 200 {success:true} | none listed | Deprecated; same behaviour as request-password-reset; logs a deprecation warning | planned | TBD |
| POST | /email-otp/reset-password | email-otp | 200 {success:true} | INVALID_OTP, OTP_EXPIRED (400), TOO_MANY_ATTEMPTS (403), USER_NOT_FOUND (400), PASSWORD_TOO_SHORT (400), PASSWORD_TOO_LONG (400) | Practically unusable in app (no mail for this type) | planned | TBD |
| POST | /email-otp/request-email-change | email-otp | not reachable in app | 400 Change email with OTP is disabled; 401 without session | Disabled in app | planned | TBD |
| POST | /email-otp/change-email | email-otp | not reachable in app | 400 Change email with OTP is disabled; 401 without session | Disabled in app | planned | TBD |
| GET | /passkey/generate-register-options | passkey | 200 WebAuthn creation options JSON | SESSION_REQUIRED (401), RESOLVE_USER_REQUIRED (400), RESOLVED_USER_INVALID (400) | WebAuthn user handle is random per request, not the Better Auth user id | planned | TBD |
| GET | /passkey/generate-authenticate-options | passkey | 200 WebAuthn request options JSON | none specific | userVerification preferred but not enforced at verify-authentication | planned | TBD |
| POST | /passkey/verify-registration | passkey | 200 passkey row | CHALLENGE_NOT_FOUND (400), FAILED_TO_VERIFY_REGISTRATION (400 or 500), YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY (401) | requireUserVerification false | planned | TBD |
| POST | /passkey/verify-authentication | passkey | 200 {session, user} with session cookie | CHALLENGE_NOT_FOUND (400), PASSKEY_NOT_FOUND (401), AUTHENTICATION_FAILED (401), UNABLE_TO_CREATE_SESSION (500), origin missing (400, no code) | requireUserVerification false, so presence only; challenge not bound to a session or user | planned | TBD |
| GET | /passkey/list-user-passkeys | passkey | 200 array of passkey rows | UNAUTHORIZED (401) | - | planned | TBD |
| POST | /passkey/delete-passkey | passkey | 200 {status:true} | PASSKEY_NOT_FOUND (404-type), UNAUTHORIZED (401, not owner), FORBIDDEN (403, extra-addresses hook) | Owner check middleware (requireResourceOwnership) not read | planned | TBD |
| POST | /passkey/update-passkey | passkey | 200 {passkey} | YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY (401), PASSKEY_NOT_FOUND (404-type), FAILED_TO_UPDATE_PASSKEY (500) | Owner check middleware (requireResourceOwnership) not read | planned | TBD |
| POST | /sign-in/social | social | 200 {url, redirect}; with idToken 200 {redirect:false, token, url, user} | PROVIDER_NOT_FOUND (404), CALLBACK_URL_REQUIRED (400) | Discord uses no PKCE | planned | TBD |
| GET or POST | /callback/:id | social | 302 to callbackURL or newUserURL | 302 error codes such as invalid_code, state_mismatch, account_not_linked, unable_to_get_user_info | Google id_token claims read without signature check; POST is converted to GET | planned | TBD |
| POST | /sign-in/oauth2 | generic-oauth | 200 {url, redirect}; no Location header | CALLBACK_URL_REQUIRED (400, via generateState) | Discovery document fetched on every sign-in and callback, not cached | planned | TBD |
| GET | /oauth2/callback/:providerId | generic-oauth | 302 to callbackURL or error URL | state_mismatch, email_is_missing, oauth_code_verification_failed, user_info_is_missing, issuer_mismatch, issuer_missing, oAuth_code_missing, account_not_linked | id_token claims decoded without signature check; iss checked only when present; missing id not checked | planned | TBD |
| POST | /oauth2/link | generic-oauth | 200 {url, redirect:true} | callbackURL required (400, no code); no session rejected | Explicit link skips trustedProviders and emailVerified checks; only the email match is enforced | planned | TBD |

Not HTTP-exposed (pathless or server-only; called via auth.api only)

| Endpoint | Plugin | Note |
|---|---|---|
| set-password (no path, /:virtual) | core | Not HTTP-routable (unconfirmed in report) |
| addMember | organization | No permission check; role not validated; server-only |
| generateTOTP | two-factor | No auth; returns current TOTP for a given secret |
| viewBackupCodes | two-factor | No auth; returns decrypted backup codes for a userId |
| createVerificationOTP | email-otp | No auth; returns plaintext OTP |
| getVerificationOTP | email-otp | No auth; returns plaintext OTP or null |

core: 27 HTTP endpoints, 1 not HTTP-exposed
organization: 21 HTTP endpoints, 1 not HTTP-exposed
two-factor: 8 HTTP endpoints, 2 not HTTP-exposed
email-otp: 9 HTTP endpoints, 2 not HTTP-exposed
passkey: 7 HTTP endpoints, 0 not HTTP-exposed
social: 2 HTTP endpoints, 0 not HTTP-exposed
generic-oauth: 3 HTTP endpoints, 0 not HTTP-exposed
