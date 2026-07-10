# Backend

[![CI](https://github.com/the-bughex-code/golang-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/the-bughex-code/golang-backend/actions/workflows/ci.yml)

A production-ready Go backend: Clean Architecture, JWT authentication, RBAC,
PostgreSQL. Built to be the foundation for a SaaS, an ERP, or a mobile API.

Go 1.26 · chi · pgx/v5 · PostgreSQL 15 · goose · zero external runtime services.

```bash
git clone https://github.com/the-bughex-code/golang-backend.git
cd golang-backend
```

---

## Quick start

You need Go, PostgreSQL, goose, golangci-lint and air. If you followed the setup
in this repository's history, you have them.

```bash
# 1. Configuration. Never commit the result.
cp .env.example .env

# 2. Generate real secrets and put them in .env
openssl rand -hex 24     # -> DB_PASSWORD
openssl rand -base64 48  # -> JWT_SECRET

# 3. Create the app role and the dev/test databases
make db-setup

# 4. Create the schema and seed roles and permissions
make migrate-up

# 5. Run it, with live reload
make dev
```

Then:

```bash
curl -s localhost:8080/health/ready | jq
open http://localhost:8080/docs        # Swagger UI (not served in production)
```

`make` on its own lists every available target.

---

## Verify it works

```bash
# Register
curl -s -X POST localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"correct-horse-battery",
       "firstName":"Alice","lastName":"Nguyen"}' | jq

# Sign in and keep the token
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"correct-horse-battery"}' \
  | jq -r .data.accessToken)

# Your own profile
curl -s localhost:8080/api/v1/profile -H "Authorization: Bearer $TOKEN" | jq

# Someone else's — 403, because the `user` role has no permissions
curl -s localhost:8080/api/v1/users -H "Authorization: Bearer $TOKEN" | jq
```

To make yourself an admin:

```bash
make psql
```
```sql
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u CROSS JOIN roles r
WHERE u.email = 'alice@example.com' AND r.name = 'admin';
```

Then sign in again. The old token still has the old permissions — it is a
signed snapshot, and it cannot be changed after the fact. That is the JWT
trade-off, working as designed.

---

## Every folder, and why it exists

```
cmd/api/main.go        The composition root. The only file that knows which
                       concrete type satisfies which interface. Builds the pool,
                       wires repositories → services → handlers → router, starts
                       the server, shuts it down gracefully.

internal/              Private to this module. The Go COMPILER refuses to let any
                       other module import anything under here. This is real,
                       enforced encapsulation — not a naming convention.

  config/              Loads and validates every setting from the environment,
                       once, at startup. Reports every problem at once, then
                       refuses to boot. Nothing below this package reads os.Getenv.

  logger/              log/slog setup. Structured JSON in production, aligned
                       text locally. Redacts password/token/secret keys before
                       they are ever written, so a slip becomes "[REDACTED]"
                       rather than a credential in your log aggregator.

  apperrors/           The single error type that crosses layer boundaries.
                       Carries two messages: one the client may read, one for
                       your logs only. That separation is a security control.

  database/            The pgx connection pool, transaction handling, health
                       checks. The ONLY package that imports pgx.

  models/              Domain entities: User, Role, Permission. No JSON tags,
                       no DB tags — so json.Marshal(user) cannot leak the
                       password hash, because the struct has no tag saying it may.

  dto/request/         What a client is allowed to SEND, plus validation rules.
                       models.User is never the target of a JSON decode, so
                       {"isAdmin":true} has nowhere to land. That is mass
                       assignment, made impossible by construction.

  dto/response/        What a client is allowed to SEE, plus the one global
                       envelope. Mapping is by hand, field by field — a
                       deliberate, reviewable checkpoint between your database
                       and the internet.

  validators/          Wraps go-playground/validator and converts its output into
                       clean, per-field messages. Written once, used by every
                       endpoint.

  repositories/        All SQL, and nothing but SQL. Translates rows into models,
                       and PostgreSQL error codes into application errors.

  services/            Business logic, and the interfaces it needs. Knows nothing
                       about HTTP. Knows nothing about pgx.

  handlers/            HTTP in, HTTP out. Bind, call one service method, translate
                       the result. No logic. If you write an `if` that encodes a
                       business rule here, it belongs in a service.

  middlewares/         Request id, logging, panic recovery, security headers,
                       CORS, rate limiting, authentication, permission checks.

  routes/              URL → handler, and which middleware guards which endpoint.
                       The security-critical file. Read it first in any review.

migrations/            goose SQL migrations. Every one is reversible; that is
                       verified by rolling the whole stack down to zero and back.

docs/                  architecture.md (read this) and the generated OpenAPI 3.1
                       document, embedded into the binary.

scripts/               setup_db.sh — creates the app role and databases.

storage/               Runtime uploads and generated files. Gitignored.

tests/                 Integration tests, behind a build tag. They need a real
                       database, because they verify promises only PostgreSQL can
                       keep: rollback, the partial unique index, ON DELETE CASCADE.
```

Unit tests are **not** here. They live next to the code they test
(`auth_service_test.go`), because a test in the same package can reach unexported
functions and `go test ./...` finds them automatically.

---

## Commands

| Command | Does |
|---|---|
| `make dev` | Run with live reload (air) |
| `make run` | Run once |
| `make build` | Static binary into `bin/`, stamped with the git commit |
| `make test` | Unit tests, race detector on, no database needed |
| `make test-integration` | Integration tests against `backend_test` |
| `make test-cover` | Coverage report → `coverage.html` |
| `make bench` | Benchmarks — use before changing the bcrypt cost |
| `make lint` | golangci-lint |
| `make fmt` | gofumpt + import grouping |
| `make vuln` | Scan dependencies for vulnerabilities this code reaches |
| `make check` | tidy + vet + lint + test. Run before you push. |
| `make migrate-up` | Apply migrations |
| `make migrate-down` | Roll back one |
| `make migrate-create name=add_orders` | New migration |
| `make db-setup` | Create role and databases |
| `make db-check-auth` | Show whether Postgres actually verifies passwords |
| `make docs` | Regenerate the OpenAPI spec |
| `make psql` | psql shell on the dev database |

---

## The request lifecycle, in one screen

```
Flutter
   │  POST /api/v1/auth/login   { "email": ..., "password": ... }
   ▼
net/http          ReadHeaderTimeout — stops Slowloris before our code runs
   ▼
RequestID         every log line and the response body carry the same id
   ▼
RequestLogger     starts the timer, puts a request-scoped logger in the context
   ▼
Recover           a panic from here down becomes a 500, not a dropped socket
   ▼
SecurityHeaders   nosniff, DENY framing, CSP
   ▼
CORS              browser-origin rules (a Flutter mobile app ignores all of this)
   ▼
RateLimit         reject a flood BEFORE the server does any expensive work
   ▼
chi router        matches the URL; this route is outside the authenticated group
   ▼
AuthHandler       bind → validate → call exactly one service method
   ▼
AuthService       the business rule: unknown email and wrong password are
                  indistinguishable, and take the same 182ms
   ▼
UserRepository    SELECT ... WHERE email = $1   ← a bind parameter, never a string
   ▼
PostgreSQL
   ▼
response.OK       the one envelope every endpoint returns
   ▼
Flutter
```

Full detail, with the reasoning behind each ordering: **[docs/architecture.md](docs/architecture.md)**.

---

## API

Base path `/api/v1`. Interactive docs at `/docs` (development only — a public
endpoint enumerating every route and error code is a gift to an attacker).

### Public

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/register` | Creates the account, grants the `user` role |
| `POST` | `/auth/login` | Returns an access + refresh token pair |
| `POST` | `/auth/refresh` | Rotates the refresh token. Unauthenticated by design |
| `POST` | `/auth/logout` | Revokes one refresh token |

### Authenticated

| Method | Path | Requires |
|---|---|---|
| `GET` | `/profile` | a valid token |
| `PATCH` | `/profile` | a valid token |
| `POST` | `/profile/change-password` | a valid token + the current password |
| `GET` | `/users` | `users:read` |
| `GET` | `/users/{id}` | `users:read` |
| `DELETE` | `/users/{id}` | `users:delete` |
| `POST` | `/users/{id}/roles` | `roles:assign` |
| `GET` | `/roles` | `roles:read` |

### Unversioned

`GET /health/live` — is the process alive? Touches nothing external.
`GET /health/ready` — can it serve? Pings the database.

Those are different questions. A liveness probe that checks the database turns a
recoverable database outage into a container restart loop across every replica.

---

## Every response has the same shape

```json
{
  "success": true,
  "message": "Signed in successfully",
  "data": { "...": "..." },
  "errors": null,
  "pagination": null,
  "meta": null,
  "timestamp": "2026-07-10T12:03:26.816782Z",
  "requestId": "hostname/FcX68IbpgJ-000002"
}
```

On failure, `success` is `false`, `data` is `null`, and `meta.code` carries a
stable machine-readable error code:

```json
{
  "success": false,
  "message": "An account with this email already exists",
  "data": null,
  "errors": [{ "field": "email", "message": "This email is already registered" }],
  "pagination": null,
  "meta": { "code": "EMAIL_TAKEN" },
  "timestamp": "2026-07-10T12:03:26.816782Z",
  "requestId": "hostname/FcX68IbpgJ-000002"
}
```

**Branch on `meta.code`, never on `message`.** The message is free to change and
to be translated. One Dart decoder handles every endpoint, success and failure.

---

## Security

Implemented, and verified by tests:

- **bcrypt cost 12** for passwords. ~180ms per hash on Apple Silicon:
  imperceptible to a human, brutally expensive to an attacker at scale.
- **No user enumeration.** An unknown email and a wrong password return the same
  code, the same message, and the same response time. Measured: 182.6ms vs
  182.2ms, a 0.5ms gap inside a 4ms noise floor.
- **JWT algorithm pinning.** `WithValidMethods` rejects the `alg: none` attack;
  `WithExpirationRequired` rejects a token that never expires. Both are real
  CVEs. Both have a test.
- **Refresh token rotation with reuse detection.** Replaying a consumed token
  revokes every session for that user.
- **Refresh tokens are stored as SHA-256 hashes**, never in plaintext.
- **RBAC by permission**, not by role, so adding a role is a database row rather
  than a code change.
- **SQL injection is structurally impossible.** Bind parameters mean data never
  enters the query text.
- **Mass assignment is impossible.** Request DTOs have no field for `isAdmin`,
  and `DisallowUnknownFields` turns the attempt into a visible 400.
- **1 MiB body cap**, so `curl -d @/dev/zero` cannot exhaust memory.
- **Two rate-limit buckets**: a permissive global one, and a strict one on
  `/auth/*` that stands between an attacker and unlimited password guesses.
- **Security headers** on every response, including errors. HSTS only in
  production over TLS — setting it on `localhost` would pin your browser and
  break every other project you develop.
- **Config refuses to boot in production** with `DB_SSLMODE=disable`, a wildcard
  CORS origin, or a JWT secret under 32 characters.
- **Logs redact** anything whose key contains `password`, `token`, `secret`,
  `authorization`, or `cookie`.

**CSRF is not applicable here**, and `docs/architecture.md` §10 explains exactly
why — and precisely when it becomes mandatory (the moment you move the token
into a cookie).

---

## Configuration

Everything comes from the environment. Nothing is hardcoded. `.env` is for
development only; in production, inject real environment variables via your
platform. A secret sitting on a production disk is a secret waiting to be read.

`config.Load()` validates on startup and reports **every** problem at once:

```
fatal: config: invalid configuration:
  - DB_MAX_CONNS must be >= 1 and DB_MIN_CONNS >= 0
  - JWT_SECRET must be at least 32 characters (generate one with: openssl rand -base64 48)
  - LOG_LEVEL must be debug|info|warn|error, got "verbose"
  - DB_SSLMODE must not be 'disable' in production; use 'require' or 'verify-full'
```

See `.env.example` — every variable is documented there with the reasoning
behind its default.

---

## Testing

```bash
make test              # unit — no database, no Docker, ~25s (bcrypt is slow on purpose)
make test-integration  # integration — needs PostgreSQL, ~2s
make test-cover        # coverage report
```

Unit tests use hand-written fakes (`internal/services/fakes_test.go`), not a
mocking framework. That is possible only because services depend on interfaces
they declare themselves — see `internal/services/ports.go`.

Integration tests verify what a fake cannot: that a transaction really rolls
back on error *and on panic*, that a nested `InTx` joins the outer transaction,
that the partial unique index really frees an email after soft deletion, and
that SQLSTATE `23505` really becomes a `409 EMAIL_TAKEN` without leaking the
constraint name.

---

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request to `main`. Four
jobs, in parallel:

| Job | Runs | Catches |
|---|---|---|
| **check** | `make check`, `make build` | lint, vet, unit tests, and an untidy `go.mod` |
| **integration** | `make test-integration` against a `postgres:15` service | a broken migration, a transaction that does not roll back |
| **security** | `make vuln` | a known CVE in code you actually call |
| **docs** | `make docs` | an OpenAPI spec that no longer matches the handler annotations |

**Every job calls a Makefile target.** Nothing in the workflow reimplements a
command, so `make check` on your laptop and `make check` in CI cannot drift
apart — and any CI failure is reproducible locally by running the target named
in the failing step.

Two of those jobs are gates that would silently pass if written carelessly, so
both were verified to *fail* when they should: changing an annotation without
running `make docs` breaks the docs job, and leaving `go.mod` untidy breaks the
check job.

`make vuln` uses govulncheck's default **symbol-level** scan, not `-scan module`.
`golang.org/x/crypto` carries an advisory against its unmaintained `openpgp`
package, marked *Fixed in: N/A*. We import `bcrypt` from that module and never
touch `openpgp`. A module-level gate would therefore fail forever, for a risk we
do not carry — and the only way to get a green build would be to ignore it. A
gate everyone ignores is worse than no gate.

---

## Adding a feature

Follow the arrows. To add `POST /api/v1/orders`:

1. `migrations/` — `make migrate-create name=create_orders`
2. `internal/models/order.go` — the entity, no tags
3. `internal/repositories/order_repository.go` — the SQL
4. `internal/services/ports.go` — declare the `OrderStore` interface you need
5. `internal/services/order_service.go` — the business rules
6. `internal/dto/request/order.go` and `dto/response/order.go`
7. `internal/handlers/order.go` — bind, call one service method, respond
8. `internal/routes/routes.go` — mount it, inside the authenticated group
9. `cmd/api/main.go` — three lines of wiring
10. `make check`

If step 3 makes you want to import `net/http`, or step 7 makes you want to write
SQL, the design is telling you something.

---

## Further reading

- **[docs/architecture.md](docs/architecture.md)** — the request lifecycle, the
  dependency rule, every trade-off and its alternative, and an honest list of
  this project's limitations.
- `http://localhost:8080/docs` — interactive OpenAPI 3.1 reference.
- `docs/swagger.json` — the spec itself. Feed it to `openapi-generator` to
  generate a typed Dart client.
