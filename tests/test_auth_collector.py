from pathlib import Path

import pytest

from sentinellite.collectors.auth import AuthEvent, collect_auth_events_from_file, parse_auth_line


def test_parse_failed_ssh_login() -> None:
    line = (
        "Aug 16 12:30:01 ubuntu-arm64-lab sshd[1201]: "
        "Failed password for invalid user admin from 192.168.1.50 port 51244 ssh2"
    )

    event = parse_auth_line(line)

    assert isinstance(event, AuthEvent)
    assert event.event_type == "ssh_failed_login"
    assert event.source == "sshd"
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.50"


def test_parse_successful_ssh_login() -> None:
    line = (
        "Aug 16 12:32:15 ubuntu-arm64-lab sshd[1210]: "
        "Accepted password for kavindu from 192.168.1.52 port 51246 ssh2"
    )

    event = parse_auth_line(line)

    assert isinstance(event, AuthEvent)
    assert event.event_type == "ssh_successful_login"
    assert event.source == "sshd"
    assert event.username == "kavindu"
    assert event.source_ip == "192.168.1.52"


def test_parse_sudo_command() -> None:
    line = (
        "Aug 16 12:33:20 ubuntu-arm64-lab sudo:  kavindu : "
        "TTY=pts/0 ; PWD=/home/kavindu ; USER=root ; COMMAND=/usr/bin/apt update"
    )

    event = parse_auth_line(line)

    assert isinstance(event, AuthEvent)
    assert event.event_type == "sudo_command"
    assert event.source == "sudo"
    assert event.username == "kavindu"
    assert event.source_ip is None
    assert "/usr/bin/apt update" in event.message


def test_ignore_unrelated_auth_line() -> None:
    line = "Aug 16 12:34:22 ubuntu-arm64-lab systemd[1]: Started Daily apt download activities."

    event = parse_auth_line(line)

    assert event is None


def test_collect_auth_events_from_sample_file() -> None:
    sample_log = Path("examples/auth_logs/sample_auth.log")

    events = collect_auth_events_from_file(sample_log)

    assert len(events) == 4
    assert events[0].event_type == "ssh_failed_login"
    assert events[1].event_type == "ssh_failed_login"
    assert events[2].event_type == "ssh_successful_login"
    assert events[3].event_type == "sudo_command"


def test_missing_auth_log_file_raises_error() -> None:
    with pytest.raises(FileNotFoundError):
        collect_auth_events_from_file("examples/auth_logs/missing.log")


def test_auth_event_to_dict() -> None:
    line = (
        "Aug 16 12:32:15 ubuntu-arm64-lab sshd[1210]: "
        "Accepted password for kavindu from 192.168.1.52 port 51246 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None

    event_dict = event.to_dict()

    assert event_dict["event_type"] == "ssh_successful_login"
    assert event_dict["username"] == "kavindu"
    assert event_dict["source_ip"] == "192.168.1.52"
