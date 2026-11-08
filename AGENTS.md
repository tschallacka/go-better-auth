# AGENTS.md

Brief for the agent that builds this repository.

## Goal

go-better-auth is an authentication library for Go, modelled on [Better Auth](https://better-auth.com) (TypeScript). It covers the same ground:

- email and password sign-in
- sessions stored in a database
- social and OAuth providers
- two-factor sign-in (TOTP)
- passkeys
- API keys
- organisations
- a plugin system

## First step: a plan

Study Better Auth's documentation and source. Then write `docs/PLAN.md` covering:

- the scope of v0.1
- the package layout
- the storage interface: Postgres via `database/sql`, and SQLite (no ORM)
- how it mounts on `net/http`

Get the Owner's approval of the plan before building.

## Rules

- Use the standard library where you can. Keep dependencies few, and justify each one in the plan.
- Code is `gofmt` and `go vet` clean.
- Every security path has tests: password hashing (argon2id), constant-time compares, CSRF, session fixation, rate limits.
- Never commit a secret.
- Work on branches and open pull requests. Do not push to `master`.
