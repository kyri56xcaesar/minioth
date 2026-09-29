# Changelog

All notable changes to minioth. Versions follow
[SemVer](https://semver.org/) for the HTTP API. Everything Go-side lives
under `internal/`, so there's no importable Go API to version. The
rationale behind each fix lives in [BACKLOG.md](BACKLOG.md).

## [Unreleased]

### Added
- `GET /v1/.well-known/ready`: 200 while the store can serve requests (the
  database answers a query; the plain files are readable and their
  directory writable), 503 otherwise. `/v1/.well-known/minioth` stays the
  liveness check.

### Fixed
- Users are stored with their real primary group. `Useradd` recorded
  `pgroup = uid`, but the user's own group gets its own gid, which differs
  from the uid once that gid is taken, so `/admin/users` reported the wrong
  primary group. Users stored that way are repaired at start (SQLite).
- Plain-file store: rewrites are atomic (a synced temp file renamed over the
  original; a reader could see a half-written or empty file), a file lock
  serializes separate minioth processes on the same directory, every write
  is checked, `Useradd` writes `mpasswd` (which makes the user exist) last,
  and a line a crash left unfinished is terminated before the next append.
  Values containing `:` or line breaks are refused.
- Token versions (plain store) take the same file lock as every other write.

## [v1.1.1] — 2026-09-28

### Changed
- Retracted v1.0.5 and v1.0.6 in `go.mod` (unauthenticated `/passwd`),
  alongside the already-retracted v1.0.0–v1.0.4. No code changes.

## [v1.1.0] — 2026-09-28

### Breaking
- **`POST /v1/passwd` now requires authentication.** It previously
  accepted a bare `{"username", "password"}` and set that user's password
  with no authentication at all, so anyone could take over any account.
  It now takes a bearer access token plus
  `{"current_password", "new_password"}`, and only ever changes the
  token's own user.

### Added
- Token revocation through a per-user token generation (`ver` claim),
  persisted in the store:
  - `POST /v1/logout` (bearer): revokes all of the caller's tokens.
  - `POST /v1/admin/revoke` (`{"uid"}`): revokes all of a user's tokens.
  - Password change and reset revoke all existing tokens. Password-reset
    tokens are now single-use.
  - Deleting a user revokes their tokens, so a reused uid can't inherit
    them.
- `PATCH /v1/user/me` (bearer): self-service update of `email`, `info`,
  `shell`. An email change resets `email_verified`.
- Concurrent-write load test for both storage backends
  (`internal/store/concurrency_test.go`).

### Fixed
- Password hashes are no longer included in any JSON response
  (`/user/me`, `/admin/users`, `/admin/groups`).
- SQLite: concurrent writes on different paths failed with
  `database is locked (SQLITE_BUSY)` and a 500. Connections now use WAL,
  a 5s busy timeout, and `BEGIN IMMEDIATE`.
- SQLite: `PATCH /admin/userpatch` stored a patched password unhashed,
  leaving it in plaintext and locking the user out.
- SQLite: `PATCH /admin/userpatch` interpolated arbitrary JSON keys as
  SQL column names. Fields are now whitelisted.

### Changed
- `go.mod` retracts `v1.0.0`–`v1.0.4`. Their tags no longer exist, so the
  module proxy can't resolve them.
- SQLite databases gain a `token_versions` table, created automatically
  on startup with no migration needed, plus `-wal`/`-shm` files beside
  the db. The plain backend gains an `mtokens` file on first revocation.

## [v1.0.6] — 2026-09-27

### Added
- Access tokens and `/v1/user/token` carry `pgroup`, the user's primary
  group id.

### Fixed
- Token refresh: login signed the refresh token with the username as its
  user id, and refresh built the new access token from the refresh
  token's claims, so refreshed tokens had `user_id=<username>` and
  `groups="not-needed"`. Refresh now re-reads the user by uid and shares
  one issuer with login.

## [v1.0.5] — 2026-09-27

First tagged release after the 2026-09 overhaul.

### Security
- The SQLite store no longer logs plaintext passwords on every login.
- Rate limiting (per-IP token bucket) on `/login`, `/register`, `/passwd`
  and the password-reset routes.

### Added
- Split into `internal/{domain,config,auth,store,server,util}` with a
  single `cmd/minioth` entrypoint.
- SQLite (`modernc.org/sqlite`, pure Go) replacing DuckDB. A fully
  working plain-file backend.
- CLI flags `-backend`, `-data-dir`, `-db-path`, `-conf`. Configurable
  root credentials, gin mode, TLS, password policy.
- Email verification and password reset (simulated delivery: token
  logged and returned, not mailed).
- `POST /v1/admin/promote`, structured `[AUDIT]` logging, RS256 signing
  with a live JWKS.
- Dockerfile and compose setup.
- Test suites for the store (including byte-level plain-file format
  tests) and the HTTP layer.

### Fixed
- Many correctness and security fixes from the overhaul: substring role
  check, refresh tokens accepted as access tokens, secrets in logs, and
  more. See the `[fixed]` entries in [BACKLOG.md](BACKLOG.md).

## v1.0.0 – v1.0.4 — retracted

Tagged at some point and later deleted from the repository. The Go
module proxy still lists them but can't serve them, so they're retracted
in `go.mod`.

[v1.1.1]: https://github.com/kyri56xcaesar/minioth/compare/v1.1.0...v1.1.1
[v1.1.0]: https://github.com/kyri56xcaesar/minioth/compare/v1.0.6...v1.1.0
[v1.0.6]: https://github.com/kyri56xcaesar/minioth/compare/v1.0.5...v1.0.6
[v1.0.5]: https://github.com/kyri56xcaesar/minioth/releases/tag/v1.0.5
