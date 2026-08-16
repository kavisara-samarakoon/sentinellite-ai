from sentinellite.detection.engine import detect_event, detect_events
from sentinellite.models.security_event import create_security_event
from sentinellite.scoring.risk import (
    ScoredAlert,
    calculate_risk_score,
    clamp_score,
    get_risk_level,
    score_rule_match,
    score_rule_matches,
)


def test_clamp_score() -> None:
    assert clamp_score(-10) == 0
    assert clamp_score(50) == 50
    assert clamp_score(120) == 100


def test_get_risk_level() -> None:
    assert get_risk_level(10) == "info"
    assert get_risk_level(30) == "low"
    assert get_risk_level(60) == "medium"
    assert get_risk_level(80) == "high"
    assert get_risk_level(90) == "critical"


def test_calculate_risk_score_without_modifiers() -> None:
    assert calculate_risk_score(50) == 50


def test_calculate_risk_score_with_modifiers() -> None:
    assert calculate_risk_score(50, modifiers=[10, 15]) == 75


def test_calculate_risk_score_caps_at_100() -> None:
    assert calculate_risk_score(90, modifiers=[20]) == 100


def test_score_failed_ssh_rule_match() -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login attempt for user admin from 192.168.1.50",
        evidence={"username": "admin", "source_ip": "192.168.1.50"},
    )

    rule_matches = detect_event(event)
    scored_alert = score_rule_match(rule_matches[0])

    assert isinstance(scored_alert, ScoredAlert)
    assert scored_alert.rule_id == "AUTH-001"
    assert scored_alert.base_score == 50
    assert scored_alert.risk_score == 50
    assert scored_alert.risk_level == "low"


def test_score_failed_ssh_rule_match_with_modifier() -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login attempt for user admin from 192.168.1.50",
    )

    rule_matches = detect_event(event)
    scored_alert = score_rule_match(rule_matches[0], modifiers=[20])

    assert scored_alert.risk_score == 70
    assert scored_alert.risk_level == "medium"


def test_score_multiple_rule_matches() -> None:
    events = [
        create_security_event(
            source="sshd",
            event_type="ssh_failed_login",
            severity="medium",
            message="Failed SSH login test",
        ),
        create_security_event(
            source="sudo",
            event_type="sudo_command",
            severity="medium",
            message="Sudo command test",
        ),
    ]

    rule_matches = detect_events(events)
    scored_alerts = score_rule_matches(rule_matches)

    assert len(scored_alerts) == 2
    assert scored_alerts[0].rule_id == "AUTH-001"
    assert scored_alerts[1].rule_id == "AUTH-003"


def test_scored_alert_to_dict() -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login test",
    )

    rule_match = detect_event(event)[0]
    scored_alert = score_rule_match(rule_match)

    scored_alert_dict = scored_alert.to_dict()

    assert isinstance(scored_alert_dict, dict)
    assert scored_alert_dict["rule_id"] == "AUTH-001"
    assert scored_alert_dict["risk_score"] == 50
    assert scored_alert_dict["risk_level"] == "low"
