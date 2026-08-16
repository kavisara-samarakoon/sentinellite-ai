import socket
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: str
    host_id: str
    source: str
    event_type: str
    severity: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    raw_data: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def create_security_event(
    source: str,
    event_type: str,
    message: str,
    severity: str = "info",
    evidence: dict[str, Any] | None = None,
    raw_data: str | None = None,
    host_id: str | None = None,
    timestamp: str | None = None,
) -> SecurityEvent:
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Allowed values: {ALLOWED_SEVERITIES}")

    if not source:
        raise ValueError("Security event source cannot be empty.")

    if not event_type:
        raise ValueError("Security event type cannot be empty.")

    if not message:
        raise ValueError("Security event message cannot be empty.")

    return SecurityEvent(
        event_id=str(uuid4()),
        timestamp=timestamp or datetime.now(UTC).isoformat(),
        host_id=host_id or socket.gethostname(),
        source=source,
        event_type=event_type,
        severity=severity,
        message=message,
        evidence=evidence or {},
        raw_data=raw_data,
    )
