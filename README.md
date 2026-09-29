# minioth

**Status: work in progress — not production ready.**

`minioth` is a small Go auth service: register/login, JWT-based sessions, and
Unix-style user/group management (uid/gid, primary groups, `useradd`/`userdel`/
`usermod`-style operations) exposed over an HTTP API built with
[gin](https://github.com/gin-gonic/gin). It plays the role of a lightweight
identity provider for other services — issuing JWTs, exposing a
`/.well-known/openid-configuration` document, and a JWKS endpoint that
publishes the live signing key — rather than being a full OIDC provider.

Module path: `github.com/kyri56xcaesar/minioth` · Go 1.26.

## What it does today

- **Register / Login** (`POST /v1/register`, `POST /v1/login`) — creates a
  user with bcrypt-hashed password, issues a JWT access token (1h, signed
  per `JWT_SIGNING_ALG`) and a refresh token (72h, always HS256) on login.
  Registration accepts an optional `email`.
- **Token lifecycle** — `POST /v1/token/refresh` mints a new access/refresh
  pair from a valid refresh token; `GET /v1/user/token` and `GET /v1/user/me`
  introspect the caller's token.
- **Revocation** — every token carries the user's *token generation*
  (`ver` claim), checked against the store on every use. `POST /v1/logout`
  (bearer) and `POST /v1/admin/revoke` (`{"uid": "..."}`) bump it,
  invalidating all of that user's access, refresh and pending
  password-reset tokens at once — "log out everywhere"; there's no
  per-session logout. Password change/reset and user deletion revoke too.
  Persisted (`token_versions` table / `mtokens` file), so it survives
  restarts.
- **Self-service profile** — `PATCH /v1/user/me` (bearer) updates the
  caller's own `email`, `info` and/or `shell`; changing the email resets
  `email_verified`. Everything else stays admin-only (`/admin/userpatch`).
- **Password change / reset** — `POST /v1/passwd` changes the caller's own
  password: bearer access token plus `{"current_password", "new_password"}`.
  `POST /v1/passwd/reset-request` + `POST /v1/passwd/reset` (unauthenticated
  reset via a short-lived, single-use signed token — see Known weaknesses
  for why this is simulated rather than emailed).
- **Email verification** — `POST /v1/verify-email/request` (authenticated,
  issues a signed 24h token for the caller's on-file email) + `GET
  /v1/verify-email?token=...` (confirms it). Simulated the same way as
  password reset: the token is logged and returned in the response, not
  emailed.
- **Admin API** (`/v1/admin/*`, gated by `AuthMiddleware("admin", ...)` or a
  named `X-Service-Secret` credential) — full CRUD on users and groups
  (`useradd`, `userdel`, `userpatch`, `usermod`, `groupadd`, `groupdel`,
  `grouppatch`, `groupmod`), `promote` (add a user to any group, gid 0
  "admin" by default — how an admin creates another admin), a
  password-verify endpoint, token revocation (`revoke`), and a raw bcrypt
  hash/verify utility endpoint. Password hashes are never included in any
  JSON response.
- **Audit logging** — every privileged admin action logs a structured
  `[AUDIT] actor=... action=... target=... result=...` line (see Known
  weaknesses for why it's log lines rather than a queryable store).
- **Well-known endpoints** — `/v1/.well-known/minioth` (liveness),
  `/v1/.well-known/ready` (readiness: 503 while the store can't serve),
  `/v1/.well-known/openid-configuration`, `/v1/.well-known/jwks.json`
  (derived live from whichever signing key is actually loaded — see
  Known weaknesses).

## Architecture

The service is split into `internal/<responsibility>` packages behind a
single `cmd/` entrypoint (previously everything lived flat in one package
at the repo root — that's gone now):

| Package | Role |
|---|---|
| `cmd/minioth` | `main()` — picks the storage backend, wires up `domain.Minioth` + `server.MService`, and starts serving. |
| `internal/domain` | Core domain: `Minioth`, `User`, `Group`, `Password` structs, the `MiniothHandler` interface, bcrypt helpers (`Hash`, `HashWithCost`, `VerifyPass`). No dependencies on any other internal package. |
| `internal/config` | `.env`-based config loading (`EnvConfig`) via `godotenv`. No internal dependencies. |
| `internal/auth` | Everything JWT (claims, HS256/RS256 signing, parsing, live JWKS generation) plus CORS and `AuthMiddleware` (bearer token + `X-Service-Secret`). Depends only on `internal/config`. |
| `internal/store` | `DBHandler` (SQLite, active by default) and `PlainHandler` (`/etc/passwd`-style flat files) — both implement `domain.MiniothHandler`. Depends on `internal/domain` and `internal/util`. |
| `internal/server` | Composition root: `MService`, `NewMService`, `Bootstrap`, `ServeHTTP`, request-model validation (`RegisterClaim`/`LoginClaim`). Routes are wiring-only (`routes_auth.go`, `routes_admin.go`, `routes_wellknown.go`); the actual request handling lives in per-group handler structs (`handlers_auth.go`'s `AuthHandler`, `handlers_admin.go`'s `AdminHandler`, `handlers_wellknown.go`'s `WellKnownHandler`) so route files stay a scannable list of `path → method`. `audit.go` holds the admin-action audit logger. Depends on `domain`, `config`, `auth`, `util`. |
| `internal/util` | A few regex validators (`IsAlphanumeric`, `IsValidUTF8String`, …) plus `SplitSelectID`, the `Select("resource?key=value")` query parser shared by both store backends. No internal dependencies. |

`domain.Minioth` is a thin dispatcher over the `MiniothHandler` interface,
so the storage backend is swappable — the caller (`cmd/minioth/main.go`)
constructs and injects whichever backend it wants
(`domain.NewMinioth("root", &store.DBHandler{DBpath: "minioth.db"})`, or a
`&store.PlainHandler{}`) rather than `domain` importing `store` directly
(that would be an import cycle, since `store` needs `domain`'s
`User`/`Group`/`Password` types).

I built a [graphify](https://github.com/safishamsi/graphify) knowledge graph
of this repo (`graphify-out/`, see `GRAPH_REPORT.md` / `graph.html`) to check
this by hand rather than assumption. It independently confirmed the shape
before an earlier round of changes — one 1050-line HTTP-layer file, a
half-implemented `PlainHandler` bridging into the live path through
`verifyPass()`, four low-cohesion communities — which led to the file split
that later became this package split. Rerun `/graphify --update` to refresh
it against the current layout.

## Storage backends

- **SQLite (`DBHandler`, active by default)** — five tables (`users`,
  `passwords`, `groups`, `user_groups`, `token_versions`), created via
  `CREATE TABLE IF NOT EXISTS` on startup, with `PRIMARY KEY`/`UNIQUE`
  constraints on `users.uid`/`username` and `groups.gid`/`groupname` (fresh
  databases only — see Known weaknesses). Root user and `admin`/`mod`/`user`
  groups (gid 0/100/1000) are seeded automatically. Id allocation is
  serialized through a package-level mutex, and every connection runs in
  WAL mode with a 5s `busy_timeout` and `BEGIN IMMEDIATE` transactions, so
  concurrent writers wait their turn instead of failing with
  `SQLITE_BUSY` (WAL adds `minioth.db-wal`/`-shm` files beside the db). Driver is [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite)
  (pure Go, no CGO) — this used to be DuckDB, a columnar OLAP engine that
  was the wrong shape for this workload (point lookups, tiny row-level
  CRUD) and dragged in Apache Arrow as a transitive dependency; SQLite is
  the right-sized embedded SQL engine for a tool this size.
- **Plain files (`PlainHandler`, fully implemented)** — colon-delimited
  files (`data/plain/mpasswd`, `mshadow`, `mgroup`, plus `mtokens` once
  any token has been revoked), modeled after
  `/etc/passwd` + `/etc/shadow` + `/etc/group`. Every `MiniothHandler`
  method now does real work (previously several were no-op stubs and
  `Authenticate` returned `(nil, nil)` on success). It's a legitimate
  alternative to SQLite for small/embedded deployments, with two caveats
  SQLite doesn't have: no locking beyond a single process, and every write
  rewrites the whole file it touches — fine for tens of users, not for
  scale.

## Known weaknesses

Tracked in [BACKLOG.md](BACKLOG.md) — what's been fixed (with rationale) and
what's still open, grouped by severity. Every fix from every session gets
logged there as it happens.

## Configuration

Copy `minioth.env.template` to `minioth.env` and fill in:

```
API_PORT=9090
IP=localhost
ISSUER=http://localhost:9090
GIN_MODE=release
TLS_CERT_FILE=
TLS_KEY_FILE=
ROOT_USERNAME=root
ROOT_PASSWORD=
ALLOWED_ORIGINS=
ALLOWED_HEADERS=
ALLOWED_METHODS=
JWT_SECRET_KEY=
JWT_REFRESH_KEY=
JWT_SIGNING_ALG=HS256
JWT_RSA_PRIVATE_KEY_PATH=
SERVICE_SECRETS=
HASH_COST=
```

`JWT_SECRET_KEY`, `JWT_REFRESH_KEY`, and `SERVICE_SECRETS` are required —
`config.go` calls `log.Fatalf` if any is empty (`SERVICE_SECRETS` also
`Fatalf`s on a malformed entry). `HASH_COST` defaults to 16 (bcrypt cost)
and is clamped to `[0, 30]`.

`JWT_SIGNING_ALG` picks how access tokens are signed: `HS256` (default,
symmetric) or `RS256` (asymmetric — set `JWT_RSA_PRIVATE_KEY_PATH` to a PEM
private key; the public half is published at `/.well-known/jwks.json`).
Refresh tokens are always HS256, regardless of this setting.

`SERVICE_SECRETS` configures the `X-Service-Secret` inter-service bypass as
named credentials: `svc-a:some-long-random-value,svc-b:another-value`. Each
service should get its own value.

`GIN_MODE` (`debug`/`release`/`test`, default `release`) is applied via
`gin.SetMode()` once config is loaded — gin's own `GIN_MODE` env var only
works if it's set in the real process environment *before* the binary
starts (gin reads it at package-init time, earlier than this or any other
`.env` value can reach it), so this is what actually controls it when set
via `minioth.env`.

`TLS_CERT_FILE`/`TLS_KEY_FILE`: set both to serve HTTPS directly
(`http.Server.ListenAndServeTLS`) instead of plain HTTP — for deployments
that won't sit behind a TLS-terminating reverse proxy. Leave both empty to
keep the default plain-HTTP behavior; setting only one is a fatal
misconfiguration, caught at startup.

`ROOT_USERNAME`/`ROOT_PASSWORD` configure the one privileged account every
backend seeds on first boot (previously hardcoded to username `root`,
password also literally `root`). Leaving `ROOT_PASSWORD` empty generates
and logs a random one once at startup (`[SECURITY] ROOT_PASSWORD not
set...`) instead of falling back to a fixed, guessable value. The
configured username is automatically off-limits for self-registration via
`/register`, same as `root`/`kubernetes`/`k8s`.

The storage backend and its path are CLI flags, not env vars — see Running.

## Running

```
go run ./cmd/minioth [-backend db|plain] [-data-dir data] [-db-path <data-dir>/minioth.db] [-conf minioth.env]
```

- `-backend` picks the `MiniothHandler` implementation: `db` (SQLite,
  default) or `plain` (flat files under `<data-dir>/plain/`).
- `-data-dir` (default `data`) is the base directory for on-disk state —
  the SQLite db (unless `-db-path` overrides it) and, under a `plain`
  subdirectory, the flat-file backend's three files. Not the repo root —
  see Known weaknesses for why that used to be the default.
- `-db-path` is only used with `-backend=db` (default `<data-dir>/minioth.db`,
  e.g. `data/minioth.db`; absolute paths work too).
- `-conf` points at the `.env` file (default `minioth.env`).

`main()` loads config first (`server.Bootstrap`, which also applies
`HASH_COST`/password-policy/JWT signing state), then constructs the chosen
backend, `domain.NewMinioth(root, handler)`, and `server.NewMService(&m,
cfg)`, then serves on `IP:API_PORT`.

### Docker

```
docker compose up --build
```

Copy `minioth.env.template` to `minioth.env` and fill it in first —
`docker-compose.yml` mounts it read-only into the container rather than
baking it into the image (the image must never ship real secrets). Data
persists in the `minioth-data` named volume, mounted at `/data`; the
default command points `-db-path` there. To use the flat-file backend
instead, uncomment the `command:` override in `docker-compose.yml`.

Building it directly:

```
docker build -t minioth .
docker run -p 9090:9090 -v minioth-data:/data -v ./minioth.env:/data/minioth.env:ro minioth
```

The image is a two-stage build (`Dockerfile`): `CGO_ENABLED=0 go build`
against `golang:1.25-alpine`, then just the static binary + CA certs on
`alpine:3.20`. `CGO_ENABLED=0` works cleanly specifically because the
SQLite driver is `modernc.org/sqlite` (pure Go) rather than a CGO one —
this wouldn't have been a clean static build with the DuckDB driver this
project used before (see Known weaknesses).

## Knowledge graph

A generated map of this codebase lives in `graphify-out/`:

- `graph.html` — interactive dependency/community graph, open in a browser.
- `GRAPH_REPORT.md` — god nodes, community breakdown, cohesion scores,
  cross-community bridges, suggested questions.
- `graph.json` — raw graph data.

Regenerate after significant changes with `/graphify --update`.
