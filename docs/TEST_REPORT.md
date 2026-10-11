# BreachWatch Test Report

## Executive Summary
BreachWatch is runnable through Docker and passed the live smoke workflow below. The tested path is suitable for an interviewer demo. Full browser accessibility review, exhaustive API fuzzing, and a fresh-clone build were not rerun in this pass.

## Functional Tests

| Feature | Test | Result | Evidence |
|---|---|---|---|
| Services | `docker compose up -d` | PASS | PostgreSQL/Redis/backend/frontend started |
| Health | `GET /api/health` | PASS | `status=ok`, database and Redis ok |
| Authentication | Analyst login | PASS | Bearer token issued |
| Ingestion | `POST /api/events/demo` | PASS | 6 events persisted |
| Dashboard | `GET /api/dashboard` | PASS | Event count increased to 12 |
| RBAC | Viewer demo-event mutation | PASS | HTTP 403 |
| Alert persistence | Alert listing | PASS | High-severity Authentication anomaly persisted |

## Security Tests

| Test | Result | Finding | Fix |
|---|---|---|---|
| Viewer privileged mutation | PASS | Server denied operation | Server-side role dependency |
| Invalid event body | PASS | HTTP 422 | Pydantic validation |
| Health failure surface | PARTIAL | Database failure path not simulated in this run | Health endpoint returns degraded database status |

## API Tests

The live checks covered health, login, demo ingestion, dashboard, alerts, and viewer authorization. The endpoint groups are implemented in `/api/auth`, `/api/events`, `/api/alerts`, `/api/rules`, `/api/audit`, and `/api/dashboard`.

## Database Tests

The dashboard count changed from the persisted event records, and the alert record remained available after service restart in the earlier acceptance run. PostgreSQL volume persistence is configured in Compose.

## UI Tests

Frontend HTTP status was 200. The previously verified analyst workflow covers login, dashboard, event explorer, alert investigation, note creation, status change, and audit display. A fresh Playwright run was not available in this pass.

## Performance Findings

Dashboard aggregation and alert serialization are synchronous and should be profiled with larger event volumes before production use. Pagination exists for events; alert lists are currently bounded by query usage rather than a complete pagination contract.

## Bugs Found

No new runtime bug was found by this smoke pass. The demo sequence can deduplicate against an existing open alert, so a second run may create events without increasing alert count.

## Bugs Fixed

No source fixes were required during this pass.

## Remaining Problems

- No refresh-token flow.
- Seed/startup uses schema creation rather than a full migration runner.
- Browser-level accessibility and destructive-action confirmation coverage should be expanded.

## Final Score

| Area | Score |
|---|---:|
| Functionality | 78 |
| Engineering depth | 73 |
| Security | 70 |
| Architecture | 72 |
| UI/UX | 76 |
| Testing | 58 |
| Documentation | 78 |
| Reliability | 65 |
| Interview readiness | 72 |
