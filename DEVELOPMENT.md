# Development

Everything needed to build and test this repository comes from one Nix flake, pinned by `flake.lock`. Nothing has to be installed system-wide apart from Nix.

## Setup

1. Install Nix with flakes enabled. The [Determinate installer](https://determinate.systems/nix-installer/) enables them by default.
2. Enter the shell from the repository root:

   ```sh
   nix develop
   ```

   The first run downloads the tools; later runs start instantly. The shell prints the versions it provides.

The shell contains:

| Tool | Used for |
|---|---|
| `go`, `gofmt` | build and test; `GOTOOLCHAIN=local` stops `go` downloading another toolchain |
| `gopls`, `goimports`, `dlv` | editor support and debugging |
| `staticcheck` | static analysis (PLAN.md section 7) |
| `postgres`, `psql` (17) | scratch databases for `pgstore` and the differential harness |
| `node` (24), `bun` | the fixture generator in `testdata/gen`, which drives the real better-auth |

`scripts/` is put on `PATH` inside the shell.

To move every tool to the current nixpkgs: `nix flake update`, then commit `flake.lock`.

## Checks

```sh
make check        # gofmt, go vet, staticcheck, go test -race
make fmt          # rewrite files with gofmt
make test-short   # quick tests without -race
```

Each target runs in every directory that holds a `go.mod`. Before the first module exists, the targets report `no Go modules yet`.

## Checks against the real better-auth

`betterauth-to-go/testdata/gen` pins better-auth 1.6.14 and drives it to record fixtures and to read what the Go code writes. Install it once (scripts off; nothing runs on install):

```sh
cd betterauth-to-go/testdata/gen && npm ci --ignore-scripts
npm run vectors        # re-record testdata/fixtures/crypto-vectors.json
```

Tests that need it skip when it is not installed. CI installs it and sets `GBA_REQUIRE_LIBRARY=1`, which turns those skips into failures.

## Scratch PostgreSQL

`pg-scratch` runs one PostgreSQL server per checkout, with its data in `.dev/pg` (git-ignored). It listens on `127.0.0.1:54317` only, with trust authentication, so it is for local development, never for real data. Set `GBA_PG_PORT` to use another port, for example when two worktrees run servers at the same time.

```sh
pg-scratch up                 # initialise on first use, start, print the URL
pg-scratch new                # create a uniquely named database, print its URL
pg-scratch createdb compat    # create a named database
pg-scratch psql -d compat     # open psql
pg-scratch down               # stop
pg-scratch reset              # stop and delete all data
```

Tests that need a database read its URL from an environment variable and skip when it is unset:

```sh
export GBA_TEST_DATABASE_URL="$(pg-scratch new)"
make test
```

Unix sockets are switched off on purpose: macOS limits a socket path to about 104 bytes, and worktree paths go past that.
