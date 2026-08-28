from pathlib import Path

import pytest

from sentinellite.collectors.auth import AuthEvent, collect_auth_events_from_file, parse_auth_line
from sentinellite.collectors.auth_sources import (
    AuthLogNotFoundError,
    AuthLogUnreadableError,
    MalformedAuthLogError,
    UnsupportedAuthLogSourceError,
)


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


@pytest.mark.parametrize(
    ("fixture_path", "expected_usernames", "expected_source_ips"),
    [
        (
            Path("examples/auth_logs/sample_ubuntu_auth.log"),
            ["labadmin", "demo-user", "demo-user"],
            ["192.0.2.10", "192.0.2.11", None],
        ),
        (
            Path("examples/auth_logs/sample_rhel_secure.log"),
            ["audit-user", "ops-user", "ops-user"],
            ["198.51.100.20", "203.0.113.21", None],
        ),
    ],
)
def test_collect_auth_events_from_traditional_linux_fixture(
    fixture_path: Path,
    expected_usernames: list[str],
    expected_source_ips: list[str | None],
) -> None:
    fixture_lines = fixture_path.read_text(encoding="utf-8").splitlines()

    events = collect_auth_events_from_file(fixture_path)

    assert len(fixture_lines) == 4
    assert [event.event_type for event in events] == [
        "ssh_failed_login",
        "ssh_successful_login",
        "sudo_command",
    ]
    assert [event.username for event in events] == expected_usernames
    assert [event.source_ip for event in events] == expected_source_ips


def test_missing_auth_log_file_raises_error() -> None:
    with pytest.raises(AuthLogNotFoundError) as error_info:
        collect_auth_events_from_file("examples/auth_logs/missing.log")

    assert isinstance(error_info.value, FileNotFoundError)


def test_directory_auth_log_path_is_unsupported(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedAuthLogSourceError, match="not a regular file"):
        collect_auth_events_from_file(tmp_path)


def test_invalid_utf8_auth_log_is_malformed(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_bytes(b"Aug 16 12:30:01 host sshd[1]: \xff\xfe")

    with pytest.raises(MalformedAuthLogError, match="not valid UTF-8"):
        collect_auth_events_from_file(log_path)


def test_permission_error_during_open_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("authentication event\n", encoding="utf-8")
    original_open = Path.open

    def deny_selected_path(path: Path, *args: object, **kwargs: object):
        if path == log_path:
            raise PermissionError("simulated permission denial")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_selected_path)

    with pytest.raises(AuthLogUnreadableError, match="simulated permission denial"):
        collect_auth_events_from_file(log_path)


def test_oserror_during_iteration_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("authentication event\n", encoding="utf-8")

    class FailingAuthLog:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self):
            return self

        def __next__(self) -> str:
            raise OSError("simulated iteration failure")

    monkeypatch.setattr(
        "sentinellite.collectors.auth.validate_auth_log_path",
        lambda path: path,
    )
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: FailingAuthLog())

    with pytest.raises(AuthLogUnreadableError, match="simulated iteration failure"):
        collect_auth_events_from_file(log_path)


def test_empty_readable_auth_log_returns_no_events(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("", encoding="utf-8")

    assert collect_auth_events_from_file(log_path) == []


def test_unrelated_only_readable_auth_log_returns_no_events(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "Aug 16 12:34:22 host systemd[1]: Started a local service.\n",
        encoding="utf-8",
    )

    assert collect_auth_events_from_file(log_path) == []


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
