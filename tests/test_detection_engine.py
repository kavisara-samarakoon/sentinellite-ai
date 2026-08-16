from sentinellite.collectors.auth import auth_event_to_security_event, parse_auth_line
from sentinellite.detection.engine import RuleMatch, detect_event, detect_events
from sentinellite.detection.rules import DEFAULT_RULES
from sentinellite.models.security_event import create_security_event


def test_default_rules_are_available() -> None:
    rule_ids = {rule.rule_id for rule in DEFAULT_RULES}

    assert "AUTH-001" in rule_ids
    assert "AUTH-002" in rule_ids
    assert "AUTH-003" in rule_ids


def test_detect_failed_ssh_login_event() -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login attempt for user admin from 192.168.1.50",
        evidence={"username": "admin", "source_ip": "192.168.1.50"},
    )

    matches = detect_event(event)

    assert len(matches) == 1
    assert isinstance(matches[0], RuleMatch)
    assert matches[0].rule_id == "AUTH-001"
    assert matches[0].rule_name == "Failed SSH Login"
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 50
    assert matches[0].evidence["username"] == "admin"


def test_detect_successful_ssh_login_event() -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_successful_login",
        severity="low",
        message="Successful SSH login for user kavindu from 192.168.1.52",
        evidence={"username": "kavindu", "source_ip": "192.168.1.52"},
    )

    matches = detect_event(event)

    assert len(matches) == 1
    assert matches[0].rule_id == "AUTH-002"
    assert matches[0].severity == "low"


def test_detect_sudo_command_event() -> None:
    event = create_security_event(
        source="sudo",
        event_type="sudo_command",
        severity="medium",
        message="User kavindu executed sudo command: /usr/bin/apt update",
        evidence={"username": "kavindu", "source_ip": None},
    )

    matches = detect_event(event)

    assert len(matches) == 1
    assert matches[0].rule_id == "AUTH-003"
    assert matches[0].category == "privilege_usage"


def test_unknown_event_has_no_match() -> None:
    event = create_security_event(
        source="system",
        event_type="unknown_event",
        severity="info",
        message="Unknown event for testing",
    )

    matches = detect_event(event)

    assert matches == []


def test_detect_multiple_events_from_auth_log_lines() -> None:
    lines = [
        (
            "Aug 16 12:30:01 ubuntu-arm64-lab sshd[1201]: "
            "Failed password for invalid user admin from 192.168.1.50 port 51244 ssh2"
        ),
        (
            "Aug 16 12:32:15 ubuntu-arm64-lab sshd[1210]: "
            "Accepted password for kavindu from 192.168.1.52 port 51246 ssh2"
        ),
        (
            "Aug 16 12:33:20 ubuntu-arm64-lab sudo:  kavindu : "
            "TTY=pts/0 ; PWD=/home/kavindu ; USER=root ; COMMAND=/usr/bin/apt update"
        ),
    ]

    auth_events = [parse_auth_line(line) for line in lines]
    security_events = [
        auth_event_to_security_event(auth_event)
        for auth_event in auth_events
        if auth_event is not None
    ]

    matches = detect_events(security_events)

    assert len(matches) == 3
    assert matches[0].rule_id == "AUTH-001"
    assert matches[1].rule_id == "AUTH-002"
    assert matches[2].rule_id == "AUTH-003"


def test_rule_match_to_dict() -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login test",
    )

    matches = detect_event(event)

    match_dict = matches[0].to_dict()

    assert isinstance(match_dict, dict)
    assert match_dict["rule_id"] == "AUTH-001"
    assert match_dict["event_type"] == "ssh_failed_login"
