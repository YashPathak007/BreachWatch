from datetime import datetime, timezone
from app.detection import default_rules

def test_rules_are_controlled_and_configurable():
    rules = default_rules()
    assert {rule["rule_key"] for rule in rules} == {"brute_force", "auth_anomaly", "suspicious_request", "privilege_change", "event_burst"}
    brute = next(rule for rule in rules if rule["rule_key"] == "brute_force")
    assert brute["config"]["threshold"] == 5
    assert brute["config"]["window_minutes"] == 5
