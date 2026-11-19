# .NET Core Web API Template for Front End Department / Back End Course

Starter ASP.NET Core Web API for full-stack internship exercises. It currently implements user registration (email + password, optional email confirmation by code or magic link) and authentication (login with optional email confirmation, JWT access/refresh tokens in HttpOnly cookies, refresh, logout) on PostgreSQL; further exercises add RBAC and more.

## Repository layout

```text
src/FEDept.BackendCourse.GroupA1.Api.Template/    API project
tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/  Integration tests
```

## Prerequisites

- .NET 10 SDK
- Docker (PostgreSQL and Mailpit for local runs; the tests start PostgreSQL via Testcontainers)

The repository pins its SDK feature band in [`global.json`](global.json). Install SDK `10.0.402` or a later `10.0.x` feature band.

Verify the installed SDK:

```bash
dotnet --version
```

## Run locally

Start PostgreSQL and [Mailpit](https://mailpit.axllent.org/) (local SMTP catcher), apply the migrations, then run the API:

```bash
docker compose up -d
dotnet tool restore
dotnet ef database update --project src/FEDept.BackendCourse.GroupA1.Api.Template
dotnet run --project src/FEDept.BackendCourse.GroupA1.Api.Template
```

Emails sent by the API are visible at `http://localhost:8025`. The schema is managed by EF Core migrations only (`src/.../Data/Migrations`); the API never creates or alters tables on startup. To add a migration after changing the model:

```bash
dotnet ef migrations add <Name> --project src/FEDept.BackendCourse.GroupA1.Api.Template --output-dir Data/Migrations
```

By default, the development profiles expose the API at:

- HTTP: `http://localhost:5117`
- HTTPS: `https://localhost:7135`

To run a specific profile:

```bash
dotnet run --project src/FEDept.BackendCourse.GroupA1.Api.Template --launch-profile https
```

If the HTTPS development certificate is not trusted, run:

```bash
dotnet dev-certs https --trust
```

## Endpoints

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Confirms that the API is running. Returns `200 OK`. |
| `POST` | `/auth/register` | Registers a guest by `email` + `password`. `201` with the active user, or `202` when email confirmation is required. |
| `POST` | `/auth/register/confirm` | Confirms with `attemptId` + `code` (OTP) or `token` (magic link). `200` with the active user. |
| `POST` | `/auth/register/resend` | Sends a new code/link for a pending `email`, at most once per 60 seconds. `202`. |
| `POST` | `/auth/login` | Signs in by `email` + `password`. `204` + auth cookies, or `202` with `attemptId` when login confirmation is on. |
| `POST` | `/auth/login/confirm` | Finishes sign-in with `attemptId` + `code` (OTP) or `token` (magic link). `204` + auth cookies. |
| `POST` | `/auth/login/resend` | Sends a new code/link for `attemptId`, at most once per 60 seconds. `202`. |
| `POST` | `/auth/refresh` | New token pair from the `refresh_token` cookie. `204` + auth cookies. |
| `POST` | `/auth/logout` | Clears both auth cookies. Always `204`. |
| `GET` | `/auth/me` | Example protected endpoint: `200` with `userId` for a valid access cookie, otherwise `401`. |

## Registration

Configuration (`Registration` section; environment variables use `__`, e.g. `Registration__ConfirmationEnabled=true`):

| Key | Meaning |
| --- | --- |
| `ConfirmationEnabled` | Scenario flag "registration": new users must confirm their email. Affects new registrations only; already issued attempts stay confirmable. Development: `true`. |
| `ConfirmationMethod` | `Otp` (6-digit code) or `MagicLink`. Chosen by the server only. |
| `HmacKey` | Base64 key, at least 32 bytes, for HMAC-SHA256 of codes/tokens. Required; a dev-only key is in `appsettings.Development.json`, other environments must supply their own (`openssl rand -base64 32`). |
| `MagicLinkUrl` | Frontend page that receives `?token=...` and POSTs it to `/auth/register/confirm` (opening the link never activates the account). |
| `RegisterRateLimit`, `ResendRateLimit` | Per-client-IP fixed window: `PermitLimit` requests per `WindowSeconds`. |

SMTP settings live in the `Smtp` section (defaults point to Mailpit on `localhost:1025`).

Behavior summary:

- Email is trimmed and lower-cased; `user+tag@example.com` is a separate address. Uniqueness is enforced by the `ux_users_email` index; a pending account already occupies its email.
- Password: 8–128 characters, at least one letter (any alphabet) and one digit; surrounding whitespace is kept. Stored as an Argon2id hash (m=19 MiB, t=2, p=1) with its own salt.
- OTP: 6 digits, 10 minutes, 5 wrong entries consume the attempt (the 5th entry can still succeed; afterwards `429`). Magic link: 32 random bytes, single use, 10 minutes. Only HMAC-SHA256 of the secret is stored and compared in constant time.
- Resend re-issues the same attempt (same `attemptId`, same method): new secret, TTL restarted, attempts reset.
- If SMTP rejects the email the pending user and attempt are kept and the API returns `503`; use resend (after the 60-second cooldown).
- Errors are RFC 9457 problem details with a machine-readable `code`: `validation_failed` (400), `invalid_confirmation` (400), `email_taken` (409), `attempts_exhausted` / `resend_too_early` / `rate_limited` / `contended` (429, with `Retry-After`), `email_delivery_failed` (503).
- No session or tokens are issued by registration. RBAC is not connected yet, so no `user` role is assigned; the code marks where it will go (same transaction as activation).
- Audit log events (IDs 1000–1030) cover registrations, email sends, confirmations and resends; passwords, hashes, codes, tokens and request bodies are never logged.

## Authentication

Settings are flat keys, so the environment variables have exactly these names (e.g. `JWT_ISSUER=https://api.example.com`). Keys are base64 of at least 32 random bytes (`openssl rand -base64 32`), and all four keys must be different. If a key is missing, malformed, short or reused, the application stops at startup and the error names the setting (never its value). `appsettings.Development.json` contains dev-only keys; every other environment must supply its own.

| Key | Meaning |
| --- | --- |
| `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` | HS256 signing keys for access (15 min) and refresh (30 days) tokens. Required, different. |
| `JWT_ISSUER`, `JWT_AUDIENCE` | `iss` / `aud` used when issuing and validating. Required. |
| `LOGIN_CHALLENGE_HMAC_KEY` | HMAC-SHA256 key for login codes and magic link secrets. Required. |
| `AUDIT_LOG_HMAC_KEY` | HMAC key for pseudonymous audit IDs of unknown emails (no address in logs). Required. |
| `LOGIN_EMAIL_CONFIRMATION_ENABLED` | `true`: a correct password is followed by an email challenge. Read per request: a change affects new logins only. Development: `true`. |
| `LOGIN_EMAIL_CONFIRMATION_METHOD` | `otp` or `magic_link`. An existing attempt keeps its own method. |
| `LOGIN_MAGIC_LINK_URL` | Frontend page; the email links to `<url>#token=<attemptId>.<secret>`. The page reads the fragment and POSTs it to `/auth/login/confirm`. |
| `FRONTEND_ORIGIN` | Exact trusted frontend origin when it differs from the API's origin. Empty (default): same origin, no CORS. |
| `FRONTEND_CROSS_SITE` | `true` when that origin is on another site: auth cookies get `SameSite=None; Secure`. |

Behavior summary:

- Cookies: `access_token` (`Path=/; Max-Age=900`) and `refresh_token` (`Path=/auth/refresh; Max-Age=2592000`), both `HttpOnly; Secure; SameSite=Strict`, host-only. Tokens never appear in a body, a JS-readable header or a URL.
- JWT payload is exactly `sub, iss, aud, iat, exp, token_use`, with HS256 only and 30 seconds of clock skew. No sessions are stored: refresh rotates the pair but does not revoke the used refresh token, and logout only clears this client's cookies.
- Every token (access check, refresh) and every login is accepted only for an existing user whose `status` is `active` (`pending`, `blocked`, `deleting`, `deleted` are refused). Roles are never read from the token; the access check passes only the `userId` on.
- Login errors are neutral: unknown email, wrong password and non-active status give the same `401 invalid_credentials` (an unknown email is checked against a dummy hash, so timing matches). Session errors are `401 invalid_session`. If the database is down the API returns `503 service_unavailable`, not `401`.
- Email challenge: OTP is 6 digits with 5 entries (the 5th is still checked, then `429 attempts_exhausted`); magic link is 32 random bytes with no entry counter. Both last 10 minutes from the last send. Resend and a repeated login are allowed once per 60 seconds; both replace the secret. Each user has at most one open attempt (partial unique index). Login, confirm and resend lock the user row and then the attempt row (`FOR UPDATE`). The attempt is committed before SMTP is contacted; if SMTP fails, the `503` still carries `attemptId` so the client can resend.
- Rate limits: `/auth/login` 30 requests/min per IP and 5 failed password checks per email+IP per 15 minutes (checked before hashing; in-memory, per instance). `/auth/refresh` 30 requests/min per IP.
- CSRF: an unsafe request whose `Origin` is not the API's own origin is accepted only from `FRONTEND_ORIGIN` with the `X-CSRF-Protection: 1` header; otherwise `403 csrf_rejected`. Requests without `Origin` (curl, server-to-server) are not affected.
- Error codes: `validation_failed`, `invalid_confirmation` (400); `invalid_credentials`, `invalid_session` (401); `csrf_rejected` (403); `rate_limited`, `resend_too_early`, `attempts_exhausted` (429, with `Retry-After`); `email_delivery_failed`, `token_issue_failed`, `service_unavailable` (503).
- Audit log events: 2000–2050 for authentication and 900–920 for rate limit, database and CSRF. They carry user IDs, attempt IDs, methods and reasons, and JWT failures are reported only as a category (`missing`, `malformed`, `signature`, `expired`, `claims`, `token_use`, `user_inactive`). Emails, passwords, hashes, codes, link tokens, JWTs, cookies and keys are never logged; the request ID comes from the logging scope.

Example requests are available in [`FEDept.BackendCourse.GroupA1.Api.Template.http`](src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http).

## OpenAPI

OpenAPI is enabled in the Development environment. After starting the API, the document is available at:

```text
http://localhost:5117/openapi/v1.json
```

The template currently exposes the OpenAPI document only; it does not include a Swagger or Scalar user interface.

## Frontend integration

The simplest setup is one origin: serve the frontend and the API from the same host, or proxy `/auth` and the API routes through the frontend dev server (for example Vite's `server.proxy`). Then no CORS or CSRF header is needed and the cookies stay `SameSite=Strict`.

For a frontend on another origin, set `FRONTEND_ORIGIN` (and `FRONTEND_CROSS_SITE=true` if it is on another site, for example another domain or `http` vs `https`). The browser must send `credentials: "include"` and the header `X-CSRF-Protection: 1` on every POST. The JavaScript never sees the tokens: on `401 invalid_session` call `POST /auth/refresh` once, then retry, or go to the login form.

## Build

```bash
dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
```

## Test

```bash
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln
```

The test project uses xUnit. Registration and authentication tests are integration tests against a real PostgreSQL started by [Testcontainers](https://dotnet.testcontainers.org/) (Docker must be running) with the real migrations applied; email delivery and time are faked.

## Repository conventions

- `.editorconfig` defines shared whitespace and C# style settings.
- `.gitignore` excludes build products, IDE-specific files, test output, and local-only configuration.
- Do not commit secrets. Use environment variables or .NET User Secrets for development credentials; `appsettings.Local.json` is ignored for non-secret local overrides.
