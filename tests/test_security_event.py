import pytest

from sentinellite.collectors.auth import auth_event_to_security_event, parse_auth_line
from sentinellite.models.security_event import SecurityEvent, create_security_event


def test_create_security_event() -> None:
    event = create_security_event(
        source="test",
        event_type="test_event",
        severity="low",
        message="Test security event",
        evidence={"key": "value"},
        raw_data="raw test line",
        host_id="test-host",
        timestamp="2026-08-16T12:00:00+00:00",
    )

    assert isinstance(event, SecurityEvent)
    assert event.source == "test"
    assert event.event_type == "test_event"
    assert event.severity == "low"
    assert event.message == "Test security event"
    assert event.evidence["key"] == "value"
    assert event.raw_data == "raw test line"
    assert event.host_id == "test-host"


def test_security_event_to_dict() -> None:
    event = create_security_event(
        source="auth",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login detected",
    )

    event_dict = event.to_dict()

    assert isinstance(event_dict, dict)
    assert "event_id" in event_dict
    assert event_dict["source"] == "auth"
    assert event_dict["event_type"] == "ssh_failed_login"
    assert event_dict["severity"] == "medium"


def test_invalid_severity_raises_error() -> None:
    with pytest.raises(ValueError):
        create_security_event(
            source="test",
            event_type="test_event",
            severity="danger",
            message="Invalid severity test",
        )


def test_empty_source_raises_error() -> None:
    with pytest.raises(ValueError):
        create_security_event(
            source="",
            event_type="test_event",
            message="Missing source",
        )


def test_auth_event_to_security_event() -> None:
    line = (
        "Aug 16 12:30:01 ubuntu-arm64-lab sshd[1201]: "
        "Failed password for invalid user admin from 192.168.1.50 port 51244 ssh2"
    )

    auth_event = parse_auth_line(line)

    assert auth_event is not None

    security_event = auth_event_to_security_event(auth_event)

    assert isinstance(security_event, SecurityEvent)
    assert security_event.source == "sshd"
    assert security_event.event_type == "ssh_failed_login"
    assert security_event.severity == "medium"
    assert security_event.evidence["username"] == "admin"
    assert security_event.evidence["source_ip"] == "192.168.1.50"
