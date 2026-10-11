from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Alert, AlertEvent, DetectionRule, SecurityEvent, Severity


RULE_CONFIG_KEYS = {
    "brute_force": {"threshold", "window_minutes", "recommended_action"},
    "auth_anomaly": {"threshold", "window_minutes", "recommended_action"},
    "suspicious_request": {"threshold", "patterns", "recommended_action"},
    "privilege_change": {"threshold", "recommended_action"},
    "event_burst": {"threshold", "window_minutes", "recommended_action"},
}


def validate_rule_config(rule_key: str, config: dict) -> dict:
    """Validate user-editable rule settings without accepting executable behavior."""
    if rule_key not in RULE_CONFIG_KEYS:
        raise ValueError("This detection rule is not configurable")
    if not isinstance(config, dict):
        raise ValueError("Rule config must be an object")
    unknown = set(config) - RULE_CONFIG_KEYS[rule_key]
    if unknown:
        raise ValueError(f"Unsupported rule config field(s): {', '.join(sorted(unknown))}")

    threshold = config.get("threshold", 1)
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 10_000:
        raise ValueError("threshold must be an integer from 1 to 10000")
    if "window_minutes" in RULE_CONFIG_KEYS[rule_key]:
        window = config.get("window_minutes", 5)
        if isinstance(window, bool) or not isinstance(window, int) or not 1 <= window <= 1_440:
            raise ValueError("window_minutes must be an integer from 1 to 1440")
    if "patterns" in RULE_CONFIG_KEYS[rule_key]:
        patterns = config.get("patterns", [])
        if not isinstance(patterns, list) or not 1 <= len(patterns) <= 50 or any(not isinstance(pattern, str) or not 1 <= len(pattern.strip()) <= 120 for pattern in patterns):
            raise ValueError("patterns must contain 1 to 50 non-empty strings of 120 characters or fewer")
    if "recommended_action" in config:
        action = config["recommended_action"]
        if not isinstance(action, str) or not 1 <= len(action.strip()) <= 1_000:
            raise ValueError("recommended_action must be a non-empty string of 1000 characters or fewer")
    return config

def _window_events(db, event: SecurityEvent, minutes: int):
    start = event.timestamp - timedelta(minutes=minutes)
    return db.scalars(select(SecurityEvent).where(SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= event.timestamp).order_by(SecurityEvent.timestamp)).all()

def evaluate_event(db: Session, event: SecurityEvent) -> list[Alert]:
    rules = db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all()
    created = []
    for rule in rules:
        cfg = rule.config or {}
        matches = []
        explanation = ""
        if rule.rule_key == "brute_force" and event.event_type == "authentication" and event.status == "failure":
            threshold, window = int(cfg.get("threshold", 5)), int(cfg.get("window_minutes", 5))
            matches = [e for e in _window_events(db, event, window) if e.event_type == "authentication" and e.status == "failure" and e.source_ip == event.source_ip and e.username == event.username]
            explanation = f"{len(matches)} failed authentication attempts for {event.username or 'unknown user'} from {event.source_ip or 'unknown source'} within {window} minutes."
        elif rule.rule_key == "auth_anomaly" and event.event_type == "authentication" and event.status == "success":
            window = int(cfg.get("window_minutes", 10))
            history = _window_events(db, event, window)
            matches = [e for e in history if e.event_type == "authentication" and e.status == "failure" and e.source_ip == event.source_ip and e.username == event.username]
            explanation = f"A successful login followed {len(matches)} recent failed attempts from the same source."
        elif rule.rule_key == "suspicious_request" and event.event_type == "http_request":
            patterns = cfg.get("patterns", ["../", "union select", "<script", "cmd.exe"])
            haystack = f"{event.message} {event.action or ''}".lower()
            if any(pattern.lower() in haystack for pattern in patterns): matches = [event]
            explanation = "The request matched a documented suspicious pattern and should be reviewed in context."
        elif rule.rule_key == "privilege_change" and event.event_type == "privilege_change" and event.status not in ("approved", "success"):
            matches = [event]; explanation = "A privilege change was recorded without an approved/success status."
        elif rule.rule_key == "event_burst":
            window = int(cfg.get("window_minutes", 1)); threshold = int(cfg.get("threshold", 20))
            matches = [e for e in _window_events(db, event, window) if e.source_ip == event.source_ip]
            explanation = f"{len(matches)} events arrived from {event.source_ip or 'unknown source'} within {window} minute(s)."
        threshold = int(cfg.get("threshold", 1))
        if len(matches) < threshold: continue
        duplicate = db.scalar(select(Alert).where(Alert.rule_id == rule.id, Alert.status.not_in(["RESOLVED", "FALSE_POSITIVE"]), Alert.source_ip == event.source_ip, Alert.username == event.username))
        if duplicate:
            duplicate.last_seen = event.timestamp
            db.add(AlertEvent(alert_id=duplicate.id, event_id=event.id))
            continue
        alert = Alert(rule_id=rule.id, title=rule.name, severity=rule.severity, explanation=explanation, recommended_action=cfg.get("recommended_action", "Review the related events and document the investigation."), source_ip=event.source_ip, username=event.username, first_seen=matches[0].timestamp, last_seen=event.timestamp)
        db.add(alert); db.flush()
        related_events = matches + ([event] if rule.rule_key == "auth_anomaly" else [])
        for related in related_events: db.add(AlertEvent(alert_id=alert.id, event_id=related.id))
        created.append(alert)
    return created

def default_rules():
    return [
        {"rule_key":"brute_force","name":"Brute-force authentication","description":"Detect repeated failed logins by source and user.","severity":Severity.HIGH.value,"config":{"threshold":5,"window_minutes":5,"recommended_action":"Confirm whether the source is expected; consider account protection and block review."}},
        {"rule_key":"auth_anomaly","name":"Authentication anomaly","description":"Detect failures followed by a successful login.","severity":Severity.HIGH.value,"config":{"threshold":1,"window_minutes":10,"recommended_action":"Review the authentication timeline and validate the successful session."}},
        {"rule_key":"suspicious_request","name":"Suspicious request pattern","description":"Detect documented injection and traversal indicators in HTTP requests.","severity":Severity.CRITICAL.value,"config":{"threshold":1,"patterns":["../","union select","<script","cmd.exe"],"recommended_action":"Inspect request context, endpoint, and originating identity."}},
        {"rule_key":"privilege_change","name":"Privilege escalation indicator","description":"Detect unusual privilege changes not marked approved.","severity":Severity.CRITICAL.value,"config":{"threshold":1,"recommended_action":"Verify the change with the system owner and inspect the actor timeline."}},
        {"rule_key":"event_burst","name":"Event burst anomaly","description":"Detect unusually high event volume from one source.","severity":Severity.MEDIUM.value,"config":{"threshold":20,"window_minutes":1,"recommended_action":"Correlate the burst with deployments, scanners, or suspicious activity."}},
    ]
