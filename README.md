# PUTZFEE — Backend

FastAPI + PostgreSQL backend for the PUTZFEE cleaning / car-wash booking
platform. Async, type-safe and timezone-aware.

## Highlights

* FastAPI 0.115 + Pydantic v2 + `databases`/asyncpg
* JWT access tokens + rotating refresh tokens (stored as SHA-256 digests)
* bcrypt password hashing with HMAC-SHA256 pre-hash (covers the 72-byte
  bcrypt limit)
* Brute-force throttling on login + IP rate-limits on auth endpoints
* Multi-language error/notification messages (fa / en / de)
* Timezone-aware scheduling (defaults to `Europe/Berlin`)
* Postgres advisory locks + a `UNIQUE(start_at)` constraint to prevent
  concurrent slot collisions
* FCM HTTP v1 push notifications (legacy server key not supported)
* Pluggable AI assistant (Gemini 1.5 Flash by default, OpenAI optional)
* Per-user & per-IP rate limiting (in-process)
* Image upload pipeline (Pillow resize + WebP/JPEG compression)

## Quickstart

```bash
# 1. Clone and create a venv
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
$EDITOR .env       # fill in DATABASE_URL, JWT_SECRET, FCM, AI keys, ...

# 3. Run database migrations
alembic upgrade head

# 4. Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Once running, OpenAPI docs are available at:

* Swagger UI — `http://localhost:8000/docs`
* ReDoc — `http://localhost:8000/redoc`

## Project layout

```
app/
├── __init__.py
├── main.py              # FastAPI factory + lifespan
├── config.py            # pydantic-settings configuration
├── database.py          # SQLAlchemy metadata + `databases` instance + locks
├── time_utils.py        # tz-aware helpers (Europe/Berlin by default)
├── i18n.py              # server-side translation table (fa/en/de)
├── deps.py              # auth + rate-limit FastAPI dependencies
├── schemas.py           # Pydantic request/response models
├── media.py             # image upload + Pillow processing
├── push.py              # FCM v1 push helpers
├── ai_provider.py       # Gemini / OpenAI adapter
└── routers/
    ├── auth.py          # /auth/* (register, login, refresh, reset)
    ├── user.py          # /user/* (me, cars, devices, notifications)
    ├── orders.py        # /orders/* (create, list, cancel, review)
    ├── scheduling.py    # /scheduling/* (propose + confirm slots)
    ├── public.py        # /public/* (home payload, reviews)
    ├── ai.py            # /ai/chat (authenticated, rate limited)
    └── admin.py         # /admin/* (services, promotions, lifecycle)
alembic/
├── env.py
└── versions/0001_initial.py
```

## Authentication

* `POST /auth/register` returns `{access_token, refresh_token, ...}`.
* `POST /auth/login` likewise.
* `POST /auth/refresh` rotates the refresh token (old one is revoked).
* `POST /auth/logout` revokes the supplied refresh token.
* `POST /auth/change-password` revokes all refresh tokens for the user.
* `POST /auth/forgot-password` issues a one-hour reset token (delivered
  via FCM in development).
* `POST /auth/reset-password` consumes a reset token and revokes all
  refresh tokens.

Admin status is granted at registration time for phones listed in
`ADMIN_PHONES` (comma-separated). This is **bootstrap only** — after the
first admin user is created, leave the variable empty in production.
There is **no** `ADMIN_KEY` backdoor.

## Scheduling

Slots are fixed-length (`SLOT_DURATION_HOURS`, default 1) and live
within `WORK_START_HOUR..WORK_END_HOUR` in the configured business
timezone (`SERVER_TIMEZONE`, default `Europe/Berlin`).

The flow is:

1. Admin proposes up to `MAX_SLOTS_PER_REQUEST` start times for a request.
2. User confirms one. The chosen slot is inserted into `appointments`
   (which has a `UNIQUE(start_at)` constraint). The other proposals are
   marked `REJECTED`.

Both steps run inside a transaction with a Postgres advisory lock on
the request id; the user-confirm path additionally takes a slot-start
advisory lock, eliminating the classic double-booking race.

## Rate limiting

`app/deps.py` ships an in-process token-bucket limiter and two FastAPI
dependency factories:

* `rate_limit(limit, window_seconds, scope)` — per client IP.
* `per_user_rate_limit(limit, window_seconds, scope)` — per user.

The AI endpoint additionally enforces minute/day quotas against
`ai_usage` so the limits survive restarts.

## Push notifications (FCM v1)

Set `FCM_PROJECT_ID` and `GOOGLE_APPLICATION_CREDENTIALS_JSON_B64`
(base64 of your service-account JSON). The server exchanges the
service-account JWT for an OAuth2 access token, caches it until expiry,
and posts to `messages:send`. Tokens that return `UNREGISTERED` or
`NOT_FOUND` are automatically pruned from `device_tokens`.

If FCM is not configured, push calls silently no-op so the rest of the
application keeps working in development.

## AI assistant

Set `AI_PROVIDER`, `AI_API_KEY` and `AI_MODEL`. Default is Google
Gemini 1.5 Flash, which is free up to a generous quota. The endpoint
(`POST /ai/chat`) requires authentication and is rate-limited per user
(per-minute + per-day) so a malicious client cannot drain the quota.

## Development conveniences

* `ENABLE_SCHEMA_CREATE=1` will call `metadata.create_all` on startup
  when `APP_ENV != production`. Useful for first-run / tests, but
  Alembic is the source of truth for production.
* `APP_ENV=development` enables CORS for `ALLOW_ORIGINS=*`.

## Security checklist

* Secrets are loaded from `.env`; never commit it. `.env.example` is the
  reference.
* CORS should be restricted in production (`ALLOW_ORIGINS=https://...`).
* `JWT_SECRET` and `PASSWORD_PEPPER` should be at least 32 random bytes.
* The legacy FCM server key is intentionally **not** supported.
* Reviews expose only masked phone numbers (`12***456`).
* `GET /user/exists` always returns `true` and is rate-limited to defeat
  enumeration.
