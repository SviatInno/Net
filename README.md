# .NET Core Web API Template for Front End Department / Back End Course

Starter ASP.NET Core Web API for full-stack internship exercises. It currently implements user registration (email + password, optional email confirmation by code or magic link) on PostgreSQL; further exercises add authentication, RBAC and more.

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

An example request is available in [`FEDept.BackendCourse.GroupA1.Api.Template.http`](src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http).

## OpenAPI

OpenAPI is enabled in the Development environment. After starting the API, the document is available at:

```text
http://localhost:5117/openapi/v1.json
```

The template currently exposes the OpenAPI document only; it does not include a Swagger or Scalar user interface.

## Frontend integration

CORS is not configured yet. Before calling this API from a browser-based frontend running on a different origin, add a CORS policy for the frontend's development URL and apply it to the request pipeline. Avoid using a permissive policy in a production environment.

## Build

```bash
dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
```

## Test

```bash
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln
```

The test project uses xUnit. Registration tests are integration tests against a real PostgreSQL started by [Testcontainers](https://dotnet.testcontainers.org/) (Docker must be running) with the real migrations applied; email delivery and time are faked.

## Repository conventions

- `.editorconfig` defines shared whitespace and C# style settings.
- `.gitignore` excludes build products, IDE-specific files, test output, and local-only configuration.
- Do not commit secrets. Use environment variables or .NET User Secrets for development credentials; `appsettings.Local.json` is ignored for non-secret local overrides.
