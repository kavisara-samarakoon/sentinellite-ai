from dataclasses import dataclass


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
]
