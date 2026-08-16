from collections.abc import Callable
from dataclasses import dataclass

from sentinellite.models.security_event import SecurityEvent

PROCESS_EVENT_TYPE = "process_observation"
PROCESS_TEMPORARY_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)
PROCESS_CPU_THRESHOLD = 80.0
PROCESS_MEMORY_THRESHOLD = 80.0
PROCESS_SUSPICIOUS_KEYWORDS = (
    "ncat",
    "socat",
    "http.server",
    "/dev/tcp/",
)


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    event_type: str
    category: str
    severity: str
    base_score: int
    description: str
    recommendation: str
    condition: Callable[[SecurityEvent], bool] | None = None

    def matches(self, event: SecurityEvent) -> bool:
        """Return whether an event matches this rule's type and optional condition."""
        if self.event_type != event.event_type:
            return False

        return self.condition is None or self.condition(event)


def matches_temporary_path_process(event: SecurityEvent) -> bool:
    """Match process observations whose executable is in a temporary path."""
    executable_path = event.evidence.get("exe")

    return isinstance(executable_path, str) and executable_path.startswith(
        PROCESS_TEMPORARY_PATHS
    )


def matches_high_resource_process(event: SecurityEvent) -> bool:
    """Match process observations at or above the CPU or memory threshold."""
    cpu_percent = event.evidence.get("cpu_percent")
    memory_percent = event.evidence.get("memory_percent")

    high_cpu = (
        isinstance(cpu_percent, (int, float))
        and not isinstance(cpu_percent, bool)
        and cpu_percent >= PROCESS_CPU_THRESHOLD
    )
    high_memory = (
        isinstance(memory_percent, (int, float))
        and not isinstance(memory_percent, bool)
        and memory_percent >= PROCESS_MEMORY_THRESHOLD
    )

    return high_cpu or high_memory


def matches_suspicious_process_keyword(event: SecurityEvent) -> bool:
    """Match narrow process keywords using only sanitized event evidence."""
    command_parts: list[str] = []

    for field_name in ("name", "exe"):
        field_value = event.evidence.get(field_name)
        if isinstance(field_value, str):
            command_parts.append(field_value)

    cmdline = event.evidence.get("cmdline")
    if isinstance(cmdline, list):
        command_parts.extend(argument for argument in cmdline if isinstance(argument, str))

    command_text = " ".join(command_parts).lower()

    return any(keyword in command_text for keyword in PROCESS_SUSPICIOUS_KEYWORDS)


DEFAULT_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="AUTH-001",
        name="Failed SSH Login",
        event_type="ssh_failed_login",
        category="authentication",
        severity="medium",
        base_score=50,
        description="A failed SSH login attempt was detected.",
        recommendation=(
            "Review the username, source IP address, and authentication logs. "
            "If repeated failures are observed, check SSH access rules and account security."
        ),
    ),
    DetectionRule(
        rule_id="AUTH-002",
        name="Successful SSH Login",
        event_type="ssh_successful_login",
        category="authentication",
        severity="low",
        base_score=20,
        description="A successful SSH login was detected.",
        recommendation=(
            "Verify that the login was expected. Review the source IP address, user account, "
            "and login time if the activity appears unusual."
        ),
    ),
    DetectionRule(
        rule_id="AUTH-003",
        name="Sudo Command Usage",
        event_type="sudo_command",
        category="privilege_usage",
        severity="medium",
        base_score=45,
        description="A sudo command execution event was detected.",
        recommendation=(
            "Review the command, user account, and working directory. Confirm that the "
            "privileged action was authorized."
        ),
    ),
    DetectionRule(
        rule_id="PROC-001",
        name="Temporary Path Process Execution",
        event_type=PROCESS_EVENT_TYPE,
        category="process_execution",
        severity="medium",
        base_score=60,
        description="A process executable is running from a commonly writable temporary path.",
        recommendation=(
            "Review the executable path, user, command line, and process origin. Confirm that "
            "execution from the temporary directory is expected."
        ),
        condition=matches_temporary_path_process,
    ),
    DetectionRule(
        rule_id="PROC-002",
        name="High Process Resource Usage",
        event_type=PROCESS_EVENT_TYPE,
        category="resource_usage",
        severity="low",
        base_score=30,
        description="A process reached the configured CPU or memory usage threshold.",
        recommendation=(
            "Observe the process over time and review its executable, user, and command line. "
            "High resource usage alone does not prove malicious activity."
        ),
        condition=matches_high_resource_process,
    ),
    DetectionRule(
        rule_id="PROC-003",
        name="Suspicious Process Keyword",
        event_type=PROCESS_EVENT_TYPE,
        category="process_behavior",
        severity="low",
        base_score=40,
        description="Sanitized process evidence contains a keyword that warrants investigation.",
        recommendation=(
            "Review the complete process context and confirm whether the identified tool or "
            "behavior is authorized. A keyword match alone is not proof of compromise."
        ),
        condition=matches_suspicious_process_keyword,
    ),
]
