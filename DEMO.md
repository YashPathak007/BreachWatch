# Five-minute walkthrough

This walkthrough uses only synthetic data and the local Docker Compose stack. The three passwords below are intentionally predictable demo values; they are not production credentials.

## Start the demo

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open <http://localhost:5173>. The API health response is at <http://localhost:8000/api/health>, and interactive OpenAPI documentation is at <http://localhost:8000/docs>.

## Seeded accounts

| Account | Password | Role | What it demonstrates |
| --- | --- | --- | --- |
| `analyst@breachwatch.local` | `AnalystPass123!` | Analyst | Full event-to-alert investigation flow |
| `viewer@breachwatch.local` | `ViewerPass123!` | Viewer | Read-only access and server-side denial of mutations |
| `admin@breachwatch.local` | `AdminPass123!` | Admin | Controlled rule changes and the audit view |

These values come from the local `.env.example` seed settings and should be replaced or removed outside the synthetic demo.

## Walkthrough

1. **Sign in as the analyst.** The login form is pre-filled with the analyst identity. The workspace opens on **Dashboard**.
2. **Generate evidence.** Click **Generate demo sequence**. The API submits six synthetic authentication events through the normal ingestion path: five failed logins followed by a successful login from the same documented source address.
3. **Read the signal.** The sequence exercises the `brute_force` and `auth_anomaly` rules, producing high-severity alerts with linked evidence rather than opaque counters.
4. **Investigate an alert.** Open **Alerts**, select an alert, review the correlated events and recommended action, then acknowledge it, add a short note, and resolve it. Each transition and note is written to the audit log.
5. **Explore the evidence.** Open **Events** and filter by severity or event type. The records are normalized and retain metadata describing their synthetic origin.
6. **Show least privilege.** Sign out and use the viewer account. Viewer access includes dashboard, events, alerts, and rules read views, but the API rejects event ingestion, alert mutations, notes, rule changes, and audit access with the appropriate authorization response.
7. **Show administration.** Sign in as the admin, open **Rules**, toggle a controlled rule, and open **Audit** to show the recorded operation.

## Resetting the local demo

The PostgreSQL volume preserves state when containers restart. To remove the local database and replay the walkthrough from a clean state:

```powershell
docker compose down -v
```

The `-v` flag deletes the local Compose database volume; do not use it if you want to keep the current demo records.

## Technical talking points

- Server-side RBAC is enforced independently of frontend visibility.
- Passwords use bcrypt and access tokens are signed, expiring JWTs.
- PostgreSQL JSON columns preserve event metadata and raw input context.
- `alert_events` correlates detections to the evidence that triggered them.
- Rule configuration is bounded JSON owned by known server implementations.
- Sensitive actions are recorded in an audit trail with actor, resource, and request context.
- The production gaps are explicit: no refresh-token flow, no distributed rate limiting, no full migration runner, and no claim of compliance certification.
