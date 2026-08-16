import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    event_type: str
    source: str
    username: str | None
    source_ip: str | None
    message: str
    raw_line: str

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for "
    r"(?:(?:invalid user )?(?P<username>\S+)) from (?P<source_ip>\S+)"
)

ACCEPTED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted password for "
    r"(?P<username>\S+) from (?P<source_ip>\S+)"
)

SUDO_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sudo:\s+(?P<username>\S+)\s+:.*COMMAND=(?P<command>.+)$"
)


def parse_auth_line(line: str) -> AuthEvent | None:
    clean_line = line.strip()

    if not clean_line:
        return None

    failed_match = FAILED_SSH_PATTERN.search(clean_line)
    if failed_match:
        username = failed_match.group("username")
        source_ip = failed_match.group("source_ip")
        return AuthEvent(
            timestamp=failed_match.group("timestamp"),
            event_type="ssh_failed_login",
            source="sshd",
            username=username,
            source_ip=source_ip,
            message=f"Failed SSH login attempt for user '{username}' from {source_ip}",
            raw_line=clean_line,
        )

    accepted_match = ACCEPTED_SSH_PATTERN.search(clean_line)
    if accepted_match:
        username = accepted_match.group("username")
        source_ip = accepted_match.group("source_ip")
        return AuthEvent(
            timestamp=accepted_match.group("timestamp"),
            event_type="ssh_successful_login",
            source="sshd",
            username=username,
            source_ip=source_ip,
            message=f"Successful SSH login for user '{username}' from {source_ip}",
            raw_line=clean_line,
        )

    sudo_match = SUDO_PATTERN.search(clean_line)
    if sudo_match:
        username = sudo_match.group("username")
        command = sudo_match.group("command")
        return AuthEvent(
            timestamp=sudo_match.group("timestamp"),
            event_type="sudo_command",
            source="sudo",
            username=username,
            source_ip=None,
            message=f"User '{username}' executed sudo command: {command}",
            raw_line=clean_line,
        )

    return None


def collect_auth_events_from_file(log_path: str | Path) -> list[AuthEvent]:
    path = Path(log_path)

    if not path.exists():
        raise FileNotFoundError(f"Authentication log file not found: {path}")

    events: list[AuthEvent] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_auth_line(line)
            if event is not None:
                events.append(event)

    return events


def auth_event_to_security_event(auth_event: AuthEvent):
    from sentinellite.models.security_event import create_security_event

    severity_map = {
        "ssh_failed_login": "medium",
        "ssh_successful_login": "low",
        "sudo_command": "medium",
    }

    return create_security_event(
        source=auth_event.source,
        event_type=auth_event.event_type,
        severity=severity_map.get(auth_event.event_type, "info"),
        message=auth_event.message,
        evidence={
            "username": auth_event.username,
            "source_ip": auth_event.source_ip,
            "original_timestamp": auth_event.timestamp,
        },
        raw_data=auth_event.raw_line,
    )
