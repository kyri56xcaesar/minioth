# Backlog / known weaknesses

Found by reading the handler code end-to-end and cross-checked against the
graphify dependency graph. Grouped by severity; all line refs are current as
of this commit. Items marked **[fixed]** were addressed in-repo; the rest are
still open.

## Security

- **[fixed] Secrets got logged.** `cfg.ToString()` now redacts
  `JWTSecretKey`, `JWTRefreshKey`, and `ServiceSecrets` (prints
  `[REDACTED]`), and the direct `log.Printf("updating jwt key...: %s", ...)`
  calls in `NewMService` were removed.
- **[fixed] Role check was a substring match.** `AuthMiddleware` now uses
  `hasGroup()`, which splits the comma-joined `Groups` claim and requires an
  exact match, instead of `strings.Contains(claims.Groups, role)`.
- **[fixed] Refresh tokens were accepted as access tokens.**
  `/v1/user/token`, `/v1/user/me`, and `AuthMiddleware` now share a single
  `parseAccessToken()` helper that only ever verifies against
  `jwtSecretKey` — the silent fallback to `jwtRefreshKey` is gone. A refresh
  token now only works at `/v1/token/refresh`.
- **[fixed, configurable] Password policy was `len >= 4`.**
  `Password.validatePassword()` now enforces a configurable policy:
  `PASSWORD_MIN_LENGTH` (default 8), `PASSWORD_MAX_LENGTH` (default 72, matching
  bcrypt's input cap), and optional `PASSWORD_REQUIRE_UPPER/LOWER/DIGIT/SPECIAL`
  toggles (all off by default, to stay backward compatible) — see
  `minioth.env.template`.
- **[fixed] No rate limiting.** Nothing stopped credential stuffing or
  brute force on `/login`, `/register`, or `/passwd`. `internal/auth`'s
  `RateLimitMiddleware` — a per-client-IP token bucket via
  `golang.org/x/time/rate`, no external store needed for a single-process
  tool like this — now guards those plus `/passwd/reset-request` and
  `/passwd/reset`. One limiter instance is shared across all of them (see
  `registerAuthRoutes`), so spreading requests across routes doesn't dodge
  the budget; exceeding it returns `429`. `RATE_LIMIT_RPS`/
  `RATE_LIMIT_BURST` (defaults 2 and 10) configure it. Caveat: in-memory,
  per-process — resets on restart, doesn't share state across multiple
  instances behind a load balancer. A distributed limiter is different,
  bigger infrastructure this project's scope doesn't call for.
- **[fixed] CORS was configured but never wired up.** `CORSMiddleware()` is
  now attached to the engine and reflects `ALLOWED_ORIGINS` /
  `ALLOWED_HEADERS` / `ALLOWED_METHODS` on cross-origin requests; with no
  origins configured it grants nothing (safe default). `getEnvs()` was also
  fixed to use `strings.Split` + trim instead of `strings.SplitAfter`, which
  previously left a trailing comma on every parsed value except the last.
- **[fixed, redesigned] `X-Service-Secret` bypass.** The bypass itself is
  intentional — a deliberate way for trusted internal services to skip the
  end-user JWT flow — but the old implementation had real problems: one
  static value shared by every caller (a leak or rotation affects
  everyone, and a request can't be attributed to whoever sent it),
  compared with `==` (not constant-time), and a wrong secret hit
  `c.Abort()` without setting a status first, so it silently returned `200
  OK` with an empty body. Now: `SERVICE_SECRETS` configures *named*
  per-service credentials (`svc:secret,svc2:secret2`), checked in constant
  time via `matchServiceSecret()` (`middleware.go`), and a bad secret
  returns an explicit `401`. This is still a shared-secret bypass, just a
  scoped and accountable one — `middleware.go` documents the next step up
  (mTLS, or short-lived per-service JWTs) if that's ever not enough.
- **[fixed] JWKS endpoint doesn't match the signing algorithm.** Access
  tokens are now signed with whichever algorithm `JWT_SIGNING_ALG`
  configures — `HS256` (default, symmetric — the secret stays private) or
  `RS256` (asymmetric). `/.well-known/jwks.json` and
  `id_token_signing_alg_values_supported` are both derived live from
  `jwtSigningAlg`/the loaded RSA key (`jwks()` in `jwt.go`): HS256
  publishes an empty key set (a JWKS is only ever meaningful for the
  asymmetric case — publishing the HMAC secret would leak it), RS256
  publishes the public key as a proper JWK with a stable `kid`. The old
  static `jwks.json` file on disk was already dead (no longer read) —
  since deleted from the repo, since it's just misleading to keep around
  once it does nothing.
- **[fixed] `forbidden_names` is case-sensitive.** `offLimits()` now
  lowercases the input before comparing, so `Root`/`ROOT`/`rOOt` are all
  caught, not just the exact string `"root"`.

## Correctness / robustness

- **[fixed] `PlainHandler.Authenticate` returns `(nil, nil)` on success**
  (`plainHandlers.go`) — now returns the authenticated `*User` (name, uid,
  pgroup, info/home/shell, group memberships), same shape as
  `DBHandler.Authenticate`.
- **[fixed] `DBHandler.Userpatch` panics on missing/wrong-typed fields.**
  The `groups.(string)` and `password.(string)` assertions now use the
  `, ok` form, so a patch payload that omits `"groups"` (the common case —
  patching just one field) no longer panics. Also: a patch with *no*
  effective fields now returns the `"no inputs"` error the admin route
  already expected but the handler never actually produced.
- **[fixed] `AuthMiddleware`/token endpoints could panic on a malformed
  header.** They used to slice `authHeader[len("Bearer "):]` without
  checking the header was at least 7 bytes long; a short `Authorization`
  header panicked. All three now share `extractBearerToken()`
  (`middleware.go`), which uses `strings.HasPrefix` + `strings.TrimPrefix`
  and returns a consistent `401` on every failure mode.
- **[fixed] `Purge()` didn't do what it said.** It called
  `os.Remove("data/*.db")` — `os.Remove` doesn't glob, so that call always
  failed (silently logged, not returned) and left DB files behind. Now
  uses `filepath.Glob("data/*.db")` and removes each match.
- **[fixed] `log.Fatalf` inside a request handler.** `GenerateAccessJWT`/
  `GenerateRefreshJWT` failures in `/login` used to call `log.Fatalf`,
  taking the whole process down on a single request's error. Both now
  return a `500` instead.
- **[fixed] `/token/refresh`'s keyfunc had inverted logic.** Its signing-method
  check was `if _, ok := ...(*jwt.SigningMethodHMAC); ok { return error }` —
  backwards from every other keyfunc in the file (which reject when the
  method *isn't* HMAC) — so it rejected the very HS256 refresh tokens
  `GenerateRefreshJWT` issues, breaking `/token/refresh` for anyone who
  actually called it. Found while extracting the shared `parseRefreshToken()`
  helper (see Design below); fixed as part of that extraction.
- **[fixed] TOCTOU races on ID assignment.** `nextId`'s `SELECT MAX(id)+1`
  used to run outside the transaction that consumed it — two concurrent
  `Useradd` calls could compute the same uid. `nextIdTx` now runs inside
  the same transaction as the insert, and a package-level `dbWriteMu`
  serializes every user/group-creating write (SQLite locks at the
  database-file level, not per-row, so there's no real row-level locking to
  fall back on). The schema also
  now has `PRIMARY KEY`/`UNIQUE` on `users.uid`/`username` and
  `groups.gid`/`groupname` as a second line of defense — note this only
  applies to freshly created tables (`CREATE TABLE IF NOT EXISTS` won't
  retrofit constraints onto an existing `minioth.db`).
- **[fixed] `DBHandler.Useradd`'s primary-group insert wasn't in its
  transaction.** It called `m.Groupadd(...)`, which ran on a separate
  `db.Exec` outside the surrounding `tx` — a rollback could leave an
  orphaned group row. `groupAddTx()` now does the insert inside whichever
  transaction is handed to it, used by both `Useradd` and the standalone
  `Groupadd`.
- **[fixed] Trailing comma in the schema.** The `passwords` table DDL in
  `initSql` had a trailing comma before the closing paren — worked because
  DuckDB (the engine at the time) tolerated it, but was fragile. Removed.
- **[fixed] `DBHandler` engine swapped from DuckDB to SQLite.** DuckDB is
  columnar/OLAP — the wrong shape for point lookups and tiny row-level CRUD,
  and its driver (`go-duckdb`) pulled in Apache Arrow + flatbuffers as
  transitive dependencies, heavy for a tool meant to stay lightweight.
  Swapped to `modernc.org/sqlite` (pure Go, no CGO) — see Storage backends
  in `README.md`. `PlainHandler` was left as a second, DB-engine-free
  option throughout.
- **[fixed] `PlainHandler` had no write lock.** Every `MiniothHandler`
  write method now takes `plainWriteMu` (a `sync.RWMutex`); reads take the
  read lock. This needed to be broader than `dbWriteMu`'s scope (which only
  wraps the two id-allocation races) because a flat file has no
  `UNIQUE`/`PRIMARY KEY` backstop the way SQLite does, and `rewriteFile`
  truncates the file with `os.Create` before rewriting it, so a concurrent
  reader could observe a half-written or momentarily empty file.
- **[fixed] Root user seeded at the wrong bcrypt cost.** `domain.HASH_COST`
  used to get set from config *after* `NewMinioth` had already seeded (and
  hashed) the root user, so the first hash always used the hardcoded
  default (16) regardless of `HASH_COST` in `.env`. Config loading and its
  side effects are now a separate step (`server.Bootstrap`) that
  `cmd/minioth/main.go` runs before constructing anything that hashes a
  password.
- **[fixed] `/admin/useradd`'s "already exists" check always matched.**
  `strings.Contains(err.Error(), "")` — any string contains the empty
  string — so every `Useradd` failure was reported as "already exists!"
  (403), masking the real error. Now checks for `"alr"`, matching
  `/register`'s equivalent check.
- **[fixed] `EnvConfig.DB` was dead.** It read env var `"DB"`, but the
  template/`.env` key was `DB_PATH` — the field could never be populated
  regardless of what `.env` contained. Removed; the DB path is a CLI flag
  now (`-db-path`), not an env var — see Running in `README.md`.
- **[fixed] `/admin/audit/logs` silently did nothing, and nothing was
  audited at all.** The route existed with an empty handler body,
  returning `200` with no content — and separately, no admin action was
  logged anywhere in an identifiable way. `audit.go` now logs a
  structured `[AUDIT] actor=... action=... target=... result=...` line
  from every mutating `AdminHandler` method, both success and failure
  paths. The route itself stays `501`, now pointing at stdout rather than
  claiming to be unimplemented outright: there's deliberately no
  persisted, queryable store behind it, since only the DB backend could
  support one symmetrically (`PlainHandler` has no query surface) and
  this project doesn't need that asymmetry.
- **[fixed] Root credentials were hardcoded.** Both backends' `Init()`
  seeded a user named `root` with password `root`, unconditionally. The
  `MiniothHandler.Init()` signature now takes the root `User` to seed
  (`Init(root User)`), built from `ROOT_USERNAME`/`ROOT_PASSWORD` in
  `cmd/minioth/main.go`; an unset `ROOT_PASSWORD` generates and logs a
  random one once at startup instead of defaulting to a fixed, guessable
  value. See Configuration in `README.md`.
- **[fixed] gin never left debug mode.** `gin.Default()` was called with
  no `gin.SetMode()` anywhere, so every boot logged gin's own warning
  about running in debug mode in production (full route table, verbose
  stack traces on panic). Setting `GIN_MODE` as a real OS env var would
  have worked, but gin reads it at package-init time — before `main()` (or
  the `.env` file `LoadConfig` loads) ever runs — so it couldn't be
  configured through `minioth.env` the way everything else is. `GinMode`
  is now applied explicitly via `gin.SetMode(cfg.GinMode)` in
  `NewMService`, defaulting to `release`.
- **[fixed] No TLS option.** The server only ever served plain HTTP,
  requiring a reverse proxy for TLS termination — undocumented, and not
  everyone deploying this will have one in front of it. `TLS_CERT_FILE`/
  `TLS_KEY_FILE` (`server.go`'s `ServeHTTP`) now switch to
  `http.Server.ListenAndServeTLS` when both are set; setting only one
  fails fast at startup instead of producing a confusing low-level error.
- **[fixed] Admin auth never actually worked on the plain backend.**
  `AuthMiddleware("admin", ...)` matches by group *name*, but
  `PlainHandler.Init()` only ever created each user's own per-username
  primary group — it never seeded the named `admin`/`mod`/`user` groups
  `DBHandler.Init()` does, and never joined root to `admin` (gid 0) the
  way `DBHandler`'s dedicated `insertRootUser` does. So no one, root
  included, could ever pass an admin-gated route under `-backend=plain`.
  Found while testing the new `/admin/promote` endpoint. Fixed:
  `seedStandardGroups()` (`plain.go`) seeds `admin`/`mod`/`user` at their
  conventional gids on `Init()`, and root is explicitly joined to `admin`
  afterward. Known remaining wrinkle, not chased further: a regular
  user's own primary group also gets `gid == uid`, and since both start
  numbering at 1000 (same as the seeded `user` group), the first
  registered user's personal group can share a gid with a different name
  — cosmetic (group lookups go by name, not gid, everywhere that
  matters), not a correctness bug.
- **[fixed] Email verification and password reset added.** Both are
  simulated rather than emailed — no SMTP dependency, matching this
  project's lightweight-identity-simulation framing (see Configuration in
  `README.md` for why root's password generation already worked this
  way): a signed, purpose-scoped, short-lived JWT (`internal/auth`'s
  `PurposeClaims` — reuses `jwtRefreshKey`, the same internal-only signing
  key refresh tokens use, with a `Purpose` claim so a verification token
  can't be replayed as a reset token or vice versa) is logged and returned
  directly in the API response instead of being mailed. No new persistent
  storage: the token's own signature and expiry are the validity check,
  the same tradeoff refresh tokens already make — see the no-revocation
  caveat above, which applies here too.
- **[fixed] No way to create another admin.** Registration and
  `/admin/useradd` had no path to grant the `admin` group, and
  `Grouppatch`'s `users` field replaces a group's *entire* member list
  rather than adding one — using it to add a single admin would silently
  drop every existing member. `AssignGroup` (new `MiniothHandler` method)
  adds one uid to one gid without touching anyone else's membership;
  `POST /admin/promote` exposes it, defaulting to gid 0 ("admin") when
  omitted.
- **[fixed] All on-disk state defaulted to the repo root.** `minioth.db`
  and `data/plain/{mpasswd,mshadow,mgroup}` were both hardcoded relative
  to wherever the binary happened to be run from — fine for `go run`, not
  where a real deployment's state belongs. `-data-dir` (default `data`,
  still relative to cwd but no longer *literally* the repo root) is now
  the one place both backends' storage locations derive from; `-db-path`
  still overrides the SQLite path independently if you want it somewhere
  else entirely (a different disk, say). `internal/store/plain.go`'s three
  path constants became package-level `var`s (`SetPlainDataDir`,
  set once at boot from `-data-dir` — same "mutable config set once at
  boot" pattern `domain.HASH_COST` already uses) since they were `const`
  before and couldn't be relocated at all.
- **[fixed] `DBHandler.Init` broke on an absolute `-db-path`.** Its
  directory-creation logic manually split `DBpath` on `/` and always
  prepended the current working directory — harmless when `-db-path` was
  always a bare filename (the only case that existed before `-data-dir`),
  but silently built a path like `$cwd/data/minioth.db` instead of
  `/data/minioth.db` for an absolute one, which then failed to create the
  right directory. Found while testing `-data-dir` with an absolute path.
  Now uses `filepath.Dir`, which handles both relative and absolute paths
  correctly.
- **[fixed] No HTTP-layer test coverage.** Every prior test exercised
  `MiniothHandler` implementations or package-internal functions directly
  — nothing dispatched an actual HTTP request through real routing and
  middleware. `internal/server/testutil_test.go` builds a real
  `gin.Engine` via the same `registerXRoutes` calls `ServeHTTP` uses
  (`PlainHandler`-backed, isolated to a temp dir per test) and dispatches
  through it with `httptest`, so these tests cover real request binding,
  status codes, and — importantly — `AuthMiddleware`'s actual gating
  behavior (no token / wrong role / service-secret bypass / admin token),
  not just the token-parsing logic in isolation. 32 tests across
  `handlers_auth_test.go` (register/login/refresh/introspect/change-password,
  the email-verification and password-reset round trips including
  cross-purpose token rejection), `handlers_admin_test.go` (CRUD, promote,
  the root-uid-0 protections, verify-password, hasher), `handlers_wellknown_test.go`,
  and `ratelimit_test.go` (429 after burst, shared budget across routes,
  unaffected unlimited routes).
- **Partially addressed: no tests.** `tests/` still only holds JSON request
  fixtures. Regression tests now live next to what they test
  (`internal/server/server_test.go`: `offLimits`;
  `internal/auth/middleware_test.go`: `matchServiceSecret`;
  `internal/store/store_test.go`: cross-backend behavior via the
  `MiniothHandler` interface (useradd/authenticate/userdel, `Userpatch`
  without a `"groups"` field, email/group-assignment round-tripping);
  `internal/store/plain_files_test.go`: the plain backend's on-disk file
  *format* specifically — actual bytes read back off disk after each
  operation, not just the Go API's return values, since a wrong field
  offset can still happen to read back something plausible-looking;
  `internal/server`'s HTTP-layer suite, see above) — concurrent-write load
  testing is the main thing still open.

## Design / maintainability

- **[fixed] One 1050-line file for the entire HTTP layer.**
  `minioth_server.go` used to mix routing, JWT issuance/parsing, request
  validation, and middleware in one file — the graphify community analysis
  independently flagged this as the lowest-cohesion cluster in the
  codebase (0.11). Split by concern: `jwt.go` (signing/parsing/JWKS),
  `middleware.go` (CORS/auth), `routes_auth.go`, `routes_admin.go`,
  `routes_wellknown.go` (one `register*Routes(rg, ...)` function per
  group), leaving `minioth_server.go` as the composition root — `MService`,
  `NewMService`, `ServeHTTP` wiring the route groups together, plus the
  request-model validation shared across more than one group. Still one
  package (`package minioth`) throughout, just no longer one file; a real
  `internal/` split is a bigger, separate call if it's ever worth it.
- **[fixed] JWT parsing logic was duplicated.** `AuthMiddleware`,
  `/user/token`, and `/user/me` each re-derived the same three
  Authorization-header checks before calling `parseAccessToken()`; that
  boilerplate is now `extractBearerToken()` (`middleware.go`), used by all
  three. `/token/refresh` had its own separate, buggy inline parse (see
  the inverted-logic fix above) — it's now `parseRefreshToken()` in
  `jwt.go`, next to `parseAccessToken()` instead of off on its own. The
  dead, exported `DecodeJWT()` — unused anywhere in the codebase, and the
  origin of the "silently try the refresh key if the access key fails"
  pattern that the earlier refresh-token-as-access-token fix removed
  everywhere else — was deleted rather than fixed, since nothing called it.
- **[fixed] `PlainHandler` was dead weight that looked alive.** Every
  `MiniothHandler` method is now a real implementation — `Groupadd`,
  `Groupdel`, `Groupmod`, `Grouppatch`, `Usermod`, `Userpatch`, `Passwd`,
  and a `Select` that actually reads the files, plus the `Authenticate`
  and `Userdel` bugs above. `Userdel` had an independent bug beyond the
  nil-return one: its parameter is a uid (matching the `MiniothHandler`
  interface and its one caller), but the old body compared it against the
  *username* field in the passwd file — so it could never have deleted
  anyone, even before you noticed the nil-return crash. `usernameForUID()`
  now does that lookup first.
- **[fixed] Naming inconsistencies.** `NewMSerivce` → `NewMService`
  (updated at its one call site, now `cmd/minioth/main.go`, and in this
  doc); the dead, `// Unused`-tagged `checkIfUserExists` in
  `plainHandlers.go` was deleted — `exists()` was already the one actually
  in use and does the same check.
