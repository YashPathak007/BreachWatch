# Security posture and limitations

BreachWatch is a defensive portfolio implementation. It demonstrates security-sensitive boundaries and an honest set of production follow-ups; it does not claim to be a complete SIEM, a hardened hosted service, or a compliance-certified product.

## Controls demonstrated

- Passwords are stored as bcrypt hashes and are not written to application logs.
- Access tokens are signed JWTs with an expiration. The API checks the user's role on every protected mutation; frontend checks only control presentation.
- Detection rules are selected from server-owned implementations. Admins can change enablement and bounded JSON configuration, but clients cannot submit executable detection code.
- SQLAlchemy parameterizes database queries. Pydantic validates event, note, and rule payloads, while pagination and upload sizes are constrained at the API boundary.
- Failed logins, alert changes, rule changes, event ingestion, notes, and demo generation create audit records.
- The demo uses RFC 5737 documentation IP addresses and marks generated event metadata as synthetic.
- CORS is configured from `CORS_ORIGINS` rather than being hard-coded to a public origin.

## Intentional demo limitations

- The frontend stores the short-lived bearer token in browser `localStorage` to keep the local walkthrough simple. There is no refresh-token flow. A hosted deployment should use a stronger session design, such as secure HttpOnly cookies with rotation and revocation.
- The local defaults include a placeholder signing key and predictable demo passwords. The Compose path reads them from `.env`; replace them before any shared or production-like use, and never commit `.env`.
- Docker Compose uses HTTP on localhost and development CORS. Put the API behind TLS, set explicit origins, and rotate signing keys in a real deployment.
- Redis is currently used for a connectivity/health check. Distributed rate limiting, centralized log shipping, alert fan-out, and background ingestion are not implemented.
- Startup uses SQLAlchemy `create_all` and an idempotent seed command rather than a full versioned migration runner.
- Detection and dashboard aggregation run synchronously in the API process. The current alert listing is bounded by query usage rather than a complete pagination contract.
- The demo has no external event connectors, full browser accessibility audit, exhaustive API fuzzing, or end-to-end threat model. All data is intended to be synthetic and local.

## Production hardening checklist

Before treating the design as a production service, add or verify:

1. Secret management, key rotation, token revocation, and a non-demo identity provider.
2. TLS termination, secure cookie/session handling, explicit CORS, security headers, and a deployment-specific network policy.
3. Distributed rate limiting, centralized structured logs, monitoring/alerting, backups, and database migration automation.
4. Independent authorization review, dependency scanning, abuse-case tests, browser accessibility coverage, and a documented retention policy for security events.

The repository's [TEST_REPORT.md](docs/TEST_REPORT.md) records the current smoke-test scope and known gaps.
