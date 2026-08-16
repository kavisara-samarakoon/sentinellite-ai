import pytest

from sentinellite.collectors.process import ProcessInfo
from sentinellite.detection.engine import detect_event
from sentinellite.models.security_event import SecurityEvent
from sentinellite.normalization.process import REDACTED_VALUE, process_to_security_event


def create_process_event(
    *,
    name: str = "worker",
    exe: str | None = "/usr/bin/worker",
    cmdline: list[str] | None = None,
    cpu_percent: float = 1.0,
    memory_percent: float = 1.0,
) -> SecurityEvent:
    process = ProcessInfo(
        pid=4242,
        name=name,
        username="analyst",
        exe=exe,
        cmdline=cmdline if cmdline is not None else [name],
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        status="running",
    )

    return process_to_security_event(process)


@pytest.mark.parametrize(
    "executable_path",
    [
        "/tmp/worker",
        "/var/tmp/worker",
        "/dev/shm/worker",
    ],
)
def test_temporary_path_process_matches_proc_001(executable_path: str) -> None:
    event = create_process_event(exe=executable_path, cmdline=[executable_path])

    matches = detect_event(event)

    assert event.severity == "info"
    assert [match.rule_id for match in matches] == ["PROC-001"]
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 60


def test_cpu_threshold_matches_proc_002() -> None:
    event = create_process_event(cpu_percent=80.0)

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["PROC-002"]
    assert matches[0].severity == "low"
    assert matches[0].base_score == 30


def test_memory_threshold_matches_proc_002() -> None:
    event = create_process_event(memory_percent=80.0)

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["PROC-002"]


@pytest.mark.parametrize(
    "cmdline",
    [
        ["ncat", "example.com", "443"],
        ["socat", "TCP-LISTEN:8080", "fork"],
        ["python3", "-m", "http.server"],
        ["bash", "-c", "echo test > /dev/tcp/example.com/443"],
    ],
)
def test_suspicious_keyword_matches_proc_003(cmdline: list[str]) -> None:
    event = create_process_event(cmdline=cmdline)

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["PROC-003"]
    assert matches[0].severity == "low"
    assert matches[0].base_score == 40


def test_normal_process_has_no_process_rule_matches() -> None:
    event = create_process_event(
        name="systemd",
        exe="/usr/lib/systemd/systemd",
        cmdline=["/usr/lib/systemd/systemd", "--system"],
        cpu_percent=2.0,
        memory_percent=0.5,
    )

    matches = detect_event(event)

    assert matches == []


def test_one_process_can_match_multiple_process_rules() -> None:
    event = create_process_event(
        name="ncat",
        exe="/tmp/ncat",
        cmdline=["ncat", "example.com", "443"],
        cpu_percent=95.0,
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == [
        "PROC-001",
        "PROC-002",
        "PROC-003",
    ]


def test_keyword_detection_uses_only_sanitized_event_evidence() -> None:
    event = create_process_event(
        name="client",
        exe="/usr/bin/client",
        cmdline=["client", "--token", "ncat"],
    )

    matches = detect_event(event)

    assert matches == []
    assert event.evidence["cmdline"] == ["client", "--token", REDACTED_VALUE]
    assert event.raw_data is None
