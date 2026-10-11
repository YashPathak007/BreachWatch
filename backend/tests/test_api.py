import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.models import Alert, AlertEvent, AuditLog, DetectionRule, SecurityEvent, User


def event(**overrides):
    return {"source": "test", "event_type": "authentication", "message": "Synthetic failure", "severity": "MEDIUM", "source_ip": "198.51.100.42", "username": "sam.operator", "status": "failure", **overrides}


def test_demo_creates_both_detections_and_complete_evidence(client, auth):
    headers = auth()
    response = client.post("/api/events/demo", headers=headers)
    assert response.status_code == 200
    assert response.json()["events_created"] == 6
    assert len(response.json()["alerts_created"]) == 2
    alerts = client.get("/api/alerts", headers=headers).json()["items"]
    by_rule = {alert["rule"]["key"]: alert for alert in alerts}
    assert len(by_rule["brute_force"]["events"]) == 5
    anomaly = by_rule["auth_anomaly"]
    assert len(anomaly["events"]) == 6
    assert any(item["status"] == "success" for item in anomaly["events"])


def test_alert_workflow_persists_notes_status_and_audit(client, auth):
    headers = auth()
    client.post("/api/events/demo", headers=headers)
    alert_id = client.get("/api/alerts", headers=headers).json()["items"][0]["id"]
    for status in ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"):
        result = client.patch(f"/api/alerts/{alert_id}/status", headers=headers, json={"status": status})
        assert result.status_code == 200
        assert result.json()["status"] == status
    assert client.post(f"/api/alerts/{alert_id}/notes", headers=headers, json={"content": "  Verified synthetic sequence.  "}).status_code == 200
    alert = client.get(f"/api/alerts/{alert_id}", headers=headers).json()
    assert alert["notes"][0]["content"] == "Verified synthetic sequence."
    actions = {log["action"] for log in client.get("/api/audit", headers=headers).json()}
    assert {"alert.status_changed", "investigation.note_added", "events.demo_generated"} <= actions


def test_viewer_cannot_mutate_or_read_audit(client, auth):
    headers = auth("VIEWER")
    assert client.get("/api/events", headers=headers).status_code == 200
    assert client.post("/api/events/demo", headers=headers).status_code == 403
    assert client.post("/api/events", headers=headers, json=event()).status_code == 403
    assert client.patch("/api/rules/1", headers=headers, json={"enabled": False}).status_code == 403
    assert client.patch("/api/alerts/1/status", headers=headers, json={"status": "RESOLVED"}).status_code == 403
    assert client.post("/api/alerts/1/notes", headers=headers, json={"content": "test"}).status_code == 403
    assert client.get("/api/audit", headers=headers).status_code == 403
    assert client.get("/api/events").status_code == 401


def test_inactive_user_cannot_log_in(client, db):
    user = db.scalar(select(User).where(User.role == "VIEWER"))
    user.is_active = False
    db.commit()
    assert client.post("/api/auth/login", json={"email": user.email, "password": "ViewerPass123!"}).status_code == 401


def test_invalid_log_file_is_atomic(client, auth, db):
    content = json.dumps(event()) + "\nnot valid json\n"
    response = client.post("/api/events/log-file", headers=auth(), files={"file": ("sample.jsonl", content, "application/json")})
    assert response.status_code == 422
    assert "line 2" in response.json()["detail"]
    assert db.scalar(select(func.count()).select_from(SecurityEvent)) == 0
    assert db.scalar(select(func.count()).select_from(Alert)) == 0
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "event.ingested")) == 0


def test_valid_log_file_persists_all_events(client, auth):
    headers = auth()
    content = json.dumps(event()) + "\n\n" + json.dumps(event(message="Second event"))
    response = client.post("/api/events/log-file", headers=headers, files={"file": ("sample.jsonl", content, "application/json")})
    assert response.status_code == 200
    assert response.json()["events_created"] == 2
    assert client.get("/api/events", headers=headers).json()["total"] == 2


@pytest.mark.parametrize("content, status", [(b" \n", 422), (b"\xff", 422)])
def test_log_file_boundaries(client, auth, content, status):
    response = client.post("/api/events/log-file", headers=auth(), files={"file": ("sample.log", content)})
    assert response.status_code == status


def test_oversized_log_file_rejected(client, auth):
    response = client.post("/api/events/log-file", headers=auth(), files={"file": ("sample.log", b"x" * 2_000_001)})
    assert response.status_code == 413


@pytest.mark.parametrize("config", [{"threshold": 0}, {"threshold": "five"}, {"window_minutes": -1}, {"patterns": [""]}, {"unknown": 1}])
def test_rule_config_is_bounded(client, auth, config):
    response = client.patch("/api/rules/1", headers=auth("ADMIN"), json={"config": config})
    assert response.status_code == 422


def test_rule_patch_retains_other_config(client, auth):
    headers = auth("ADMIN")
    response = client.patch("/api/rules/1", headers=headers, json={"config": {"threshold": 6}, "enabled": False})
    assert response.status_code == 200
    rule = response.json()
    assert rule["config"]["threshold"] == 6
    assert rule["config"]["window_minutes"] == 5
    assert rule["enabled"] is False


def test_event_search_and_pagination_are_server_side(client, auth):
    headers = auth()
    for username in ("sam.operator", "sam.operator", "another.user"):
        assert client.post("/api/events", headers=headers, json=event(username=username)).status_code == 200
    result = client.get("/api/events?search=sam.operator&page_size=1&page=2", headers=headers).json()
    assert result["total"] == 2
    assert len(result["items"]) == 1
    assert result["items"][0]["username"] == "sam.operator"


def test_dashboard_buckets_hours_and_preserves_calendar_date(client, auth, db):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db.add_all(SecurityEvent(timestamp=timestamp, source="test", event_type="test", severity="LOW", message="count me") for timestamp in (now - timedelta(days=1), now - timedelta(minutes=2), now - timedelta(minutes=1), now))
    db.commit()
    result = client.get("/api/dashboard", headers=auth()).json()
    assert result["total_events"] == 4
    assert len(result["events_over_time"]) == 24
    assert sum(point["value"] for point in result["events_over_time"]) == 3
    assert len({point["name"] for point in result["events_over_time"]}) == 24


def test_whitespace_note_rejected(client, auth):
    headers = auth()
    client.post("/api/events/demo", headers=headers)
    alert_id = client.get("/api/alerts", headers=headers).json()["items"][0]["id"]
    assert client.post(f"/api/alerts/{alert_id}/notes", headers=headers, json={"content": " \n "}).status_code == 422
