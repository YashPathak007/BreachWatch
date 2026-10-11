# API

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

## Authentication

`POST /api/auth/login` accepts `{ "email": "...", "password": "..." }` and returns a bearer access token. Send it as `Authorization: Bearer <token>`.

## Main endpoints

- `GET /api/health`
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`
- `POST /api/events` for validated normalized event input
- `POST /api/events/demo` for a bounded synthetic sequence (ADMIN/ANALYST)
- `POST /api/events/log-file` for UTF-8 JSON-lines `.jsonl`/`.log` uploads, 2 MB maximum
- `GET /api/events` with `page`, `page_size`, `search`, `severity`, `event_type`, `source_ip`, `username`
- `GET /api/alerts`, `GET /api/alerts/{id}`
- `PATCH /api/alerts/{id}/status`, `POST /api/alerts/{id}/notes`
- `GET /api/rules`, `PATCH /api/rules/{id}` (ADMIN only)
- `GET /api/audit` (ADMIN/ANALYST)
- `GET /api/dashboard`

All mutation endpoints reject unauthenticated requests and enforce role permissions server-side.
