from __future__ import annotations

import re
from collections.abc import Sequence

from sentinellite.collectors.process import ProcessInfo
from sentinellite.models.security_event import SecurityEvent, create_security_event

REDACTED_VALUE = "[REDACTED]"

SENSITIVE_OPTIONS = {
    "--password",
    "--token",
}

SENSITIVE_OPTION_ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<option>--(?:password|token))=(?P<value>.*)$",
    flags=re.IGNORECASE,
)

SENSITIVE_ENVIRONMENT_ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<key>(?:API_KEY|SECRET_KEY))=(?P<value>.*)$",
    flags=re.IGNORECASE,
)

URL_CREDENTIALS_PATTERN = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<credentials>[^/@\s]+)@",
    flags=re.IGNORECASE,
)


def _redact_embedded_value(argument: str) -> str:
    option_match = SENSITIVE_OPTION_ASSIGNMENT_PATTERN.match(argument)
    if option_match:
        return f"{option_match.group('option')}={REDACTED_VALUE}"

    environment_match = SENSITIVE_ENVIRONMENT_ASSIGNMENT_PATTERN.match(argument)
    if environment_match:
        return f"{environment_match.group('key')}={REDACTED_VALUE}"

    return URL_CREDENTIALS_PATTERN.sub(
        rf"\g<scheme>{REDACTED_VALUE}@",
        argument,
    )


def redact_process_command_line(cmdline: Sequence[str]) -> list[str]:
    """Return a copy of a process command line with known sensitive values redacted."""
    redacted_cmdline: list[str] = []
    redact_next_argument = False

    for argument in cmdline:
        if redact_next_argument:
            redacted_cmdline.append(REDACTED_VALUE)
            redact_next_argument = False
            continue

        redacted_argument = _redact_embedded_value(argument)
        redacted_cmdline.append(redacted_argument)

        if argument.lower() in SENSITIVE_OPTIONS:
            redact_next_argument = True

    return redacted_cmdline


def process_to_security_event(process: ProcessInfo) -> SecurityEvent:
    """Convert collected process facts into a sanitized security observation."""
    redacted_cmdline = redact_process_command_line(process.cmdline)

    return create_security_event(
        source="process",
        event_type="process_observation",
        severity="info",
        message=f"Observed process '{process.name}' with PID {process.pid}",
        evidence={
            "pid": process.pid,
            "name": process.name,
            "username": process.username,
            "exe": process.exe,
            "cmdline": redacted_cmdline,
            "cmdline_redacted": redacted_cmdline != process.cmdline,
            "cpu_percent": process.cpu_percent,
            "memory_percent": process.memory_percent,
            "status": process.status,
        },
        raw_data=None,
    )
