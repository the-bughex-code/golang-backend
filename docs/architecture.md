# Architecture

This document explains how the project is put together, why each decision was
made, and what the alternatives cost. Read it once before touching the code.

---

## 1. The one rule

**Dependencies point inward, and never back out.**

```
cmd/api  ──▶  handlers  ──▶  services  ──▶  repositories  ──▶  database
                  │              │                │
                  └──────────────┴────────────────┴──────▶  models, apperrors
```

Read it as: *handlers know about services; services do not know handlers exist.*

Concretely, and enforced by the compiler:

| Layer | May import | Must never import |
|---|---|---|
| `models` | nothing of ours | anything |
| `apperrors` | `net/http` (for status codes) | any other layer |
| `repositories` | `models`, `apperrors`, `database` | `services`, `handlers`, `net/http` |
| `services` | `models`, `apperrors`, `repositories` (for filter types only) | `handlers`, `net/http` |
| `handlers` | `services`, `dto`, `apperrors` | `repositories`, `pgx` |
| `routes` | `handlers`, `middlewares` | `services`, `repositories` |

If you ever find yourself importing `net/http` in a service, or `pgx` in a
handler, the design has been violated. That import is the alarm.

### Why this matters practically

Swapping PostgreSQL for something else means rewriting `repositories`. Nothing
above it changes. Adding a gRPC interface alongside REST means adding a sibling
to `handlers`. Nothing below it changes. Testing a business rule needs neither a
database nor an HTTP server.

---

## 2. The request lifecycle

Follow one real request all the way down: a Flutter app signing a user in.

### Step 0 — Flutter

```dart
final res = await http.post(
  Uri.parse('https://api.example.com/api/v1/auth/login'),
  headers: {'Content-Type': 'application/json'},
  body: jsonEncode({'email': 'alice@example.com', 'password': 'hunter2'}),
);
```

### Step 1 — `net/http` accepts the connection

Before any of our code runs, `http.Server` enforces its timeouts
(`cmd/api/main.go`). `ReadHeaderTimeout` bounds how long the client may take to
send its headers. Without it a single client can hold a connection open forever
by sending one byte per second — the Slowloris attack. The zero value of
`http.Server` has **no timeouts at all**.

### Step 2 — Middleware chain (`internal/routes/routes.go`)

The order is behaviour, not style. Each layer wraps the next:

```
RequestID          assign an id; every log line and the response carry it
  └─ RequestLogger  start the timer; put a request-scoped logger in the context
      └─ Recover     from here down, a panic becomes a 500 instead of a dropped socket
          └─ SecurityHeaders   nosniff, DENY framing, CSP
              └─ CORS           browser-origin rules (irrelevant to mobile)
                  └─ RateLimit  reject a flood before doing any real work
                      └─ Timeout  give the request a deadline
                          └─ RateLimit (auth)   a second, stricter bucket
                              └─ handler
```

Three of those orderings are load-bearing:

- **`Recover` must be inside `RequestLogger`.** A deferred function only covers
  frames already on the stack, so `Recover` cannot catch a panic in something
  that ran before it. Putting it inside means the logger both installs the
  context logger `Recover` uses, *and* still records the resulting 500.
- **`RateLimit` must be before `Authenticate`.** Otherwise a flood of login
  attempts makes the server run bcrypt — 300ms of CPU — for every guess before
  the limiter ever sees them. That is a denial of service with a free
  password-cracking oracle attached.
- **`CORS` must run before routing.** A browser preflight is an `OPTIONS`
  request to a path that has no `OPTIONS` handler.

### Step 3 — Router (`internal/routes/routes.go`)

chi matches `POST /api/v1/auth/login` to `AuthHandler.Login`. This route sits
*outside* the authenticated group, deliberately — you cannot require a token to
obtain a token.

Everything inside `r.Group(func(r chi.Router) { r.Use(Authenticate) ... })` is
protected. **A route added inside that block is safe by default; a route added
outside it is public by default.** That is why this file is the one to read
first in a security review.

### Step 4 — Handler (`internal/handlers/auth.go`)

```go
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req request.Login
    if err := bind(w, r, h.validator, &req); err != nil {
        response.Error(w, r, err)   // 400 or 422
        return
    }
    pair, user, err := h.auth.Login(r.Context(), req.Email, req.Password)
    if err != nil {
        response.Error(w, r, err)   // 401 or 403
        return
    }
    response.OK(w, r, "Signed in successfully", response.Auth{ ... })
}
```

Every handler in this project has that exact shape: bind, call **one** service
method, translate the result. When they all look alike, a reviewer notices
instantly when one does not.

`bind` (`internal/handlers/bind.go`) does five things, each guarding a real
failure:

1. Rejects a non-JSON `Content-Type`.
2. Caps the body at 1 MiB, so `curl -d @/dev/zero` cannot exhaust memory.
3. Rejects **unknown fields**, so `{"isAdmin": true}` is a visible 400 rather
   than a silently ignored mass-assignment attempt.
4. Rejects a second JSON value, so `{"a":1}{"b":2}` cannot smuggle a payload.
5. **Normalises, then validates** — so `" Alice@Example.COM "` is accepted, not
   rejected for containing a space.

### Step 5 — Service (`internal/services/auth_service.go`)

This is where business rules live, and the only place they live.

```go
user, err := s.users.GetByEmail(ctx, email)
if err != nil {
    if apperrors.IsKind(err, apperrors.KindNotFound) {
        burnPasswordTime(password)      // ← spend the same ~300ms
        return nil, nil, errInvalidCredentials()
    }
    return nil, nil, err
}
if err := VerifyPassword(user.PasswordHash, password); err != nil {
    return nil, nil, err                // same error, same message
}
```

`burnPasswordTime` performs a throwaway bcrypt comparison. Without it, an
unknown email returns in microseconds while a known one takes ~300ms, and an
attacker who can time your responses can discover which of a million addresses
have accounts, without ever guessing a password. **Measured on this machine
after the fix: 182.6ms vs 182.2ms — a 0.5ms difference, inside the 4ms noise
floor.**

The service knows nothing about HTTP. It returns an `*apperrors.AppError`, and
something else decides that means 401.

### Step 6 — Repository (`internal/repositories/user_repository.go`)

```go
const q = `SELECT ` + userColumns + ` FROM users WHERE email = $1 AND deleted_at IS NULL`
u, err := scanUser(r.db.Querier(ctx).QueryRow(ctx, q, email))
return u, mapError(err, "user")
```

`$1` is a **bind parameter**. The SQL text and the data travel to PostgreSQL
separately, so a value can never be parsed as SQL. This is what makes injection
structurally impossible — not escaping, not a sanitising function, but the fact
that data never enters the query text. (Verified: `'; DROP TABLE users; --`
submitted as a search term returns zero rows and leaves the table intact.)

`mapError` is the seam between "PostgreSQL" and "the rest of the program". Above
it, nobody knows what pgx is:

| PostgreSQL says | The application hears | The client sees |
|---|---|---|
| `pgx.ErrNoRows` | `KindNotFound` | 404 `NOT_FOUND` |
| SQLSTATE `23505` on `users_email_unique` | `KindConflict` | 409 `EMAIL_TAKEN` |
| SQLSTATE `23503` | `KindConflict` | 409 `REFERENCE_NOT_FOUND` |
| anything else | `KindInternal` | 500 `INTERNAL_ERROR` |

Note the last row. An error we did not deliberately classify becomes a server
fault, because by definition it is one we did not expect. Failing closed is the
safe direction.

### Step 7 — PostgreSQL

`Querier(ctx)` returns the in-flight transaction if the context carries one, and
the pool otherwise. That is why a repository method can participate in a
transaction without having a `tx` parameter, and without knowing it.

### Step 8 — Response (`internal/dto/response/response.go`)

`response.Error` is the global error handler. Every failure in the entire
application funnels through it:

```go
appErr := apperrors.From(err)           // anything unclassified → Internal
if status >= 500 { log.Error(...) }     // with the wrapped cause
else             { log.Warn(...) }      // 4xx are not bugs; do not drown the logs
write(w, r, status, Envelope{ Success: false, Message: appErr.Message, ... })
```

The client receives `appErr.Message`. It never receives `appErr.err`, the
wrapped cause. That separation is a security control:
`pq: duplicate key value violates unique constraint "users_email_key"` tells an
attacker your table name, column name and index name. "Email already registered"
tells them nothing.

---

## 3. The response envelope

Every endpoint returns the same eight fields, always present:

```json
{
  "success": true,
  "message": "Signed in successfully",
  "data": { },
  "errors": null,
  "pagination": null,
  "meta": null,
  "timestamp": "2026-07-10T12:03:26.816782Z",
  "requestId": "hostname/FcX68IbpgJ-000002"
}
```

**Why fields are not `omitempty`.** The payload is a few bytes larger. In
exchange, your Dart client never has to distinguish "key absent" from "key
null", and `ApiResponse<T>.fromJson` is written once and handles every endpoint,
including every failure. A stable shape is worth more than a stable byte count.

**Why `requestId`.** When a user reports a bug, that string finds the exact
request in your logs. It is generated by `chi`'s `RequestID` middleware, which
honours an inbound `X-Request-Id`, so a mobile client can supply its own and
correlate its logs with yours.

**Why `success` duplicates the HTTP status.** Some proxies and SDKs swallow the
status code. A body that says `success: false` is impossible to misread.

### Error codes are the contract

Branch on `meta.code`, never on `message`. The message is free to change and to
be translated. Codes in use:

`VALIDATION_FAILED` · `EMAIL_TAKEN` · `INVALID_CREDENTIALS` · `ACCOUNT_DISABLED` ·
`TOKEN_MISSING` · `TOKEN_MALFORMED` · `TOKEN_INVALID` · `TOKEN_EXPIRED` ·
`REFRESH_TOKEN_INVALID` · `REFRESH_TOKEN_EXPIRED` · `REFRESH_TOKEN_REVOKED` ·
`PERMISSION_DENIED` · `NOT_FOUND` · `RATE_LIMITED` · `CANNOT_DELETE_SELF` ·
`INTERNAL_ERROR`

`TOKEN_EXPIRED` is distinct from `TOKEN_INVALID` on purpose: the first means
"call `/auth/refresh`", the second means "send the user back to the login
screen".

---

## 4. Dependency Injection, the Go way

There is no framework, no container, no reflection. `cmd/api/main.go` is a
function you read top to bottom:

```go
userRepo := repositories.NewUserRepository(db)
authSvc  := services.NewAuthService(userRepo, roleRepo, refreshRepo, tokenSvc, db, clock)
authH    := handlers.NewAuthHandler(authSvc, validate)
```

### The trick that makes it work

`services.NewAuthService` accepts an `AuthUserStore` — an interface **declared
in the services package**, listing only the five methods that authentication
actually uses.

`*repositories.UserRepository` satisfies it *without importing it, without
naming it, without knowing it exists.* Go interfaces are implicit.

So the dependency arrow points from `services` to an interface `services` owns.
It never points at `repositories`. That is Dependency Inversion, and it buys
three things at once:

1. **Testability.** `internal/services/fakes_test.go` is a 250-line in-memory
   fake. Every service test runs with no database, no Docker, no mocks.
2. **Interface Segregation.** `AuthService` *cannot* call `List`, because
   `AuthUserStore` does not have it. The compiler enforces the boundary.
3. **A compile-time check of the wiring.** If the repository ever stops
   satisfying the interface, `main.go` fails to build. The seam is verified
   for free, at build time.

### Why there is no `interfaces/` package

A central interfaces package inverts all three benefits. Every consumer depends
on one fat interface it mostly does not use, and the package becomes an import
bottleneck that eventually cycles. The idiom is: **define an interface where it
is consumed, not where it is implemented.**

### Why there is no `utils/` or `helpers/`

Neither name describes a responsibility — they describe the absence of one.
Every codebase that has them grows a 5,000-line `utils.go` that everything
imports and that eventually imports back, creating cycles. A function lives in
the package that owns its concept: password hashing sits next to authentication;
`FullName()` is a method on `User`.

---

## 5. Transactions

The service layer needs atomicity but must not know that atomicity is spelled
`BEGIN`/`COMMIT`:

```go
err := s.tx.InTx(ctx, func(ctx context.Context) error {
    if err := s.users.Create(ctx, user); err != nil { return err }
    role, err := s.roles.GetByName(ctx, "user")
    if err != nil { return err }
    return s.roles.AssignToUser(ctx, user.ID, role.ID)
})
```

Either both rows exist, or neither does. `InTx` puts the transaction in the
context; `db.Querier(ctx)` finds it there; repositories participate without a
`tx` parameter.

**The honest trade-off.** This is *implicit*. Reading a repository method alone,
you cannot tell whether it runs in a transaction. The alternative — threading a
`tx` argument through every signature — is explicit but taxes every line of the
codebase forever, and every non-transactional caller must pass `nil`.

We chose implicit because the failure mode is benign: forgetting `Querier(ctx)`
means your query runs outside the transaction, and an integration test catches it
immediately. `tests/integration_test.go` verifies commit, rollback-on-error,
rollback-on-panic, and that a nested `InTx` joins the outer transaction rather
than committing independently.

---

## 6. Authentication

Two tokens, doing two different jobs.

| | Access token | Refresh token |
|---|---|---|
| Format | JWT (HS256) | 256 random bits |
| Lifetime | 15 minutes | 30 days |
| Stored server-side | no | yes, as a SHA-256 hash |
| Revocable | **no** | yes |
| Carries | user id, roles, permissions | nothing |

**Access tokens cannot be revoked.** That is the price of statelessness: the
server verifies the signature and asks the database nothing. Their blast radius
is bounded only by how quickly they expire, hence 15 minutes.

**Refresh tokens are just a database row**, which is exactly what makes them
revocable. We store `sha256(token)`, never the token. If the table leaks, an
attacker holds hashes, and a hash cannot be presented to the API.

SHA-256 for the refresh token, bcrypt for the password. The difference is
entropy: a refresh token is 256 random bits, so there is no dictionary to attack
and a slow hash would only mean every refresh costs 300ms of CPU. A password
might be `hunter2`, so its hash must be *deliberately* slow.

### Rotation and reuse detection

Every refresh consumes the old token and issues a new one, so a given refresh
token is valid exactly once.

If an **already-revoked** token is presented, something is wrong: either an
attacker stole a token and is using it after the real user rotated it, or the
real user is replaying one the attacker rotated. We cannot tell which — so we
revoke **every** session for that user and force a fresh login. This turns a
silent, permanent compromise into a visible, bounded one.

### The two lines that prevent the classic JWT attacks

```go
jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
jwt.WithExpirationRequired(),
```

Without the first, an attacker rewrites the token header to `{"alg":"none"}`,
strips the signature, and a library that obeys the token performs no verification
at all. Without the second, a token with no `exp` claim is a permanent
credential. Both are real CVEs, filed against many JWT libraries in many
languages.

**The rule: never let the token tell you how to verify the token.**
`internal/services/token_test.go` contains a test for each attack.

### The trade-off of putting permissions in the token

The auth middleware answers "may this user do X?" from the token alone — zero
database queries on the hot path. The cost is that the token is a **snapshot**:
revoke someone's admin role and they keep it until their access token expires,
at most `JWT_ACCESS_TTL`.

Fifteen minutes of stale authorisation is acceptable for nearly every
application. When it is not — banking, emergency lockout — shrink the TTL to
~60s, or look permissions up per request and cache them in Redis.

---

## 7. Authorization: permissions, not roles

Endpoints assert the **capability** they need:

```go
r.With(middlewares.RequirePermission(models.PermissionUsersDelete)).
    Delete("/{id}", d.Users.Delete)
```

Not `RequireRole("admin")`. The day you add a "support" role that may read users
but not delete them, the permission version requires **one row** in
`role_permissions`. The role version requires editing twenty handlers.

Roles are how capabilities are bundled for humans. That bundling belongs in
data, not in code.

Seeded by `migrations/00004_seed_rbac.sql`:

- `admin` — every permission.
- `user` — **no permissions at all**, deliberately. Reading your own profile is
  gated by *being authenticated*, not by a permission. Permissions exist to
  answer "may this person act on **other** people's data?". Granting
  `users:read` to every account would let anyone enumerate the user table.

---

## 8. Database decisions

**`UUID`, not `BIGSERIAL`.** A sequential id in a public URL leaks information:
`/users/1` is your first customer, and `/users/50000` tells a competitor how many
you have. It also makes enumeration trivial.

**UUIDv7, not v4.** v4 is fully random, so inserts scatter through random leaf
pages of the primary key's B-tree, fragmenting it. v7 puts a millisecond
timestamp in the high bits, so new rows append to the right edge, like an integer
sequence. Generated by the application (`uuid.NewV7()`), because the service
needs the id before the `INSERT`.

**`TIMESTAMPTZ`, never `TIMESTAMP`.** `TIMESTAMP` stores no timezone, so the same
value means different instants to different readers. There is no performance
difference. Using `TIMESTAMP` is a bug waiting for a daylight-saving transition.

**A partial unique index**, not a plain one:

```sql
CREATE UNIQUE INDEX users_email_unique ON users (email) WHERE deleted_at IS NULL;
```

Uniqueness applies only to live rows, so an email frees up once its account is
soft-deleted — which is what users expect. A plain `UNIQUE(email)` blocks
re-registration forever.

**`updated_at` is maintained by a trigger**, not by Go. If a DBA runs an `UPDATE`
by hand, or a second service writes to the table, an application-side timestamp
is simply wrong. A trigger cannot be bypassed.

**Composite primary keys index their leftmost prefix.** `PRIMARY KEY (user_id,
role_id)` makes "which roles does this user have?" fast for free, and "which
users have this role?" a sequential scan. That is why `user_roles_role_id_idx`
exists. This asymmetry catches people constantly.

**Soft deletion has a price**, stated plainly: every read query must filter
`deleted_at IS NULL`, forever. Forget once and deleted users reappear. This
project pays that price in exactly one place — the repository — and nowhere else.

---

## 9. What is deliberately *not* here

| Not included | Why | When to add it |
|---|---|---|
| `pkg/` | `internal/` is compiler-enforced private. An empty `pkg/` is a folder without a purpose. | The day another module must import your code. |
| Docker | You asked to skip it, and PostgreSQL runs natively. | When you need reproducible CI, or a second service. |
| gRPC / protobuf | This is a REST API for a Flutter client. `protoc` would compile nothing. | Service-to-service calls where JSON overhead matters. |
| Redis | The rate limiter's counters live in one process's memory. | When you run more than one replica — see below. |
| `sqlc` | Raw SQL teaches you what the database is doing. | Once you are comfortable with SQL and want compile-time query checking. |
| Email verification | The column and the model method exist; the sending does not. | Before you allow password reset. |

### Known limitations, honestly

1. **The rate limiter is per-process.** Three replicas behind a load balancer
   each permit the full rate, so the real limit is 3×. It also keys on IP:
   everyone behind one corporate NAT shares a bucket, and a botnet has one bucket
   per node. It is still worth having — it stops a single misbehaving client, a
   runaway retry loop, and casual credential stuffing, at the cost of one map
   lookup.

2. **`clientIP` reads `RemoteAddr`, not `X-Forwarded-For`.** Any client can
   forge that header. It is only trustworthy when a proxy you control overwrites
   it *and* nothing can reach your server except through that proxy. If you
   deploy behind exactly one such load balancer, add `chimw.RealIP` to the chain
   in `routes.go` — but only then.

3. **Search uses `ILIKE '%term%'`**, which cannot use a B-tree index and is a
   sequential scan. Fine for an admin screen over thousands of rows. At millions,
   add a trigram index:
   ```sql
   CREATE EXTENSION pg_trgm;
   CREATE INDEX users_search_idx ON users USING gin (email gin_trgm_ops);
   ```

4. **Offset pagination** (`LIMIT n OFFSET m`) makes PostgreSQL walk and discard
   all `m` preceding rows, so page 5,000 is genuinely slow, and rows can be
   skipped or repeated when data changes between requests. Right for an admin
   table a human pages through; switch to keyset pagination for infinite scroll.

5. **`golangci-lint`'s `shadow` check is disabled.** It flags
   `if err := f(); err != nil` whenever an `err` exists in an enclosing scope —
   the most idiomatic line in Go. It produced 10 findings here, all false
   positives. The Go team ships it as experimental for this reason.

6. **The Swagger UI page gets a looser Content-Security-Policy than the API.**
   `default-src 'none'; sandbox` is correct for JSON and fatal for an HTML page:
   Swagger UI loaded with a 200 and rendered a blank white screen, because the
   browser downloaded its script and stylesheet and then refused to execute
   them. Nothing appeared as a failed request.

   `middlewares.contentSecurityPolicy` therefore serves `docsCSP` — which allows
   `'self'` and `'unsafe-inline'` — for `/docs` and `/docs/*`, and `apiCSP` for
   everything else. `'unsafe-inline'` is acceptable there and nowhere else: the
   route is not mounted in production, the inline script is one we ship, and no
   user input reaches it. `internal/middlewares/security_test.go` pins all of
   this, including that a lookalike path such as `/docsomething` still gets the
   strict policy.

---

## 10. A note on CSRF

**This API does not need CSRF protection, and here is exactly why.**

A CSRF attack works because a browser *automatically* attaches cookies to any
request to your domain, including one triggered by a form on `evil.com`. The
victim's credential rides along without their knowledge.

This API authenticates with `Authorization: Bearer <token>`. A browser never
attaches that header automatically. `evil.com` cannot read your token out of the
victim's app storage (that is what the same-origin policy prevents), and without
the header the request is simply unauthenticated.

**CSRF protection becomes mandatory the moment you put the access token in a
cookie.** If you ever do — and there are good reasons to, `HttpOnly` cookies
resist XSS better than `localStorage` — you must add:

- `SameSite=Lax` or `Strict` on the cookie, and
- a synchroniser token or double-submit cookie on every state-changing request.

Until then, requiring `Content-Type: application/json` (which `bind` does) is
already a small hardening measure: a cross-origin form cannot send that content
type without triggering a CORS preflight, which your server will refuse.

---

## 11. Where to add things

| You want to | Touch |
|---|---|
| Add an endpoint | `dto/request` → `services` → `handlers` → `routes` |
| Add a table | `migrations/` (`make migrate-create name=...`) → `models` → `repositories` |
| Add a permission | `migrations/` seed → `models/rbac.go` constant → `routes.go` |
| Change a business rule | `services/` only. If you are editing a handler, stop. |
| Change an error's HTTP status | `apperrors/apperrors.go`, `Kind.HTTPStatus()`. One place. |
| Add a config value | `config/config.go` + `.env.example` + `.env` |
| Add a response field | `dto/response/` — never expose a `models` type directly |
