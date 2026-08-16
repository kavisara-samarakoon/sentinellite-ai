from sentinellite.collectors.process import ProcessInfo
from sentinellite.models.security_event import SecurityEvent
from sentinellite.normalization.process import (
    REDACTED_VALUE,
    process_to_security_event,
    redact_process_command_line,
)


def create_process(cmdline: list[str]) -> ProcessInfo:
    return ProcessInfo(
        pid=4242,
        name="python3",
        username="analyst",
        exe="/usr/bin/python3",
        cmdline=cmdline,
        cpu_percent=12.5,
        memory_percent=3.5,
        status="running",
    )


def test_process_to_security_event_preserves_sanitized_evidence() -> None:
    process = create_process(["python3", "worker.py", "--mode", "safe"])

    event = process_to_security_event(process)

    assert isinstance(event, SecurityEvent)
    assert event.source == "process"
    assert event.event_type == "process_observation"
    assert event.severity == "info"
    assert event.message == "Observed process 'python3' with PID 4242"
    assert event.raw_data is None
    assert event.evidence == {
        "pid": 4242,
        "name": "python3",
        "username": "analyst",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3", "worker.py", "--mode", "safe"],
        "cmdline_redacted": False,
        "cpu_percent": 12.5,
        "memory_percent": 3.5,
        "status": "running",
    }


def test_redact_process_command_line_redacts_separate_sensitive_values() -> None:
    cmdline = [
        "client",
        "--password",
        "password-value",
        "--token",
        "token-value",
    ]

    redacted = redact_process_command_line(cmdline)

    assert redacted == [
        "client",
        "--password",
        REDACTED_VALUE,
        "--token",
        REDACTED_VALUE,
    ]
    assert cmdline[2] == "password-value"
    assert cmdline[4] == "token-value"


def test_redact_process_command_line_redacts_inline_sensitive_values() -> None:
    cmdline = [
        "client",
        "--password=password-value",
        "--TOKEN=token-value",
        "API_KEY=api-key-value",
        "secret_key=secret-key-value",
    ]

    redacted = redact_process_command_line(cmdline)

    assert redacted == [
        "client",
        f"--password={REDACTED_VALUE}",
        f"--TOKEN={REDACTED_VALUE}",
        f"API_KEY={REDACTED_VALUE}",
        f"secret_key={REDACTED_VALUE}",
    ]


def test_redact_process_command_line_redacts_url_credentials() -> None:
    cmdline = [
        "client",
        "https://username:password@example.com/private",
        "--url=postgresql://database-user:database-password@db.example.com/app",
    ]

    redacted = redact_process_command_line(cmdline)

    assert redacted == [
        "client",
        f"https://{REDACTED_VALUE}@example.com/private",
        f"--url=postgresql://{REDACTED_VALUE}@db.example.com/app",
    ]


def test_process_to_security_event_does_not_mutate_or_leak_raw_cmdline() -> None:
    original_cmdline = ["client", "--token", "token-value"]
    process = create_process(original_cmdline.copy())

    event = process_to_security_event(process)

    assert process.cmdline == original_cmdline
    assert event.evidence["cmdline"] == ["client", "--token", REDACTED_VALUE]
    assert event.evidence["cmdline_redacted"] is True
    assert "token-value" not in str(event.to_dict())
    assert event.raw_data is None
