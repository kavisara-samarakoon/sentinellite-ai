from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sentinellite.explanations.models import AlertExplanation


@dataclass(frozen=True, slots=True)
class AlertExplanationTemplate:
    """Deterministic investigation guidance for one known detection rule."""

    rule_id: str
    title: str
    summary: str
    why_it_matched_template: str
    possible_causes: list[str]
    recommended_actions: list[str]
    confidence: str

    def to_explanation(
        self,
        evidence_summary: Mapping[str, object] | None = None,
    ) -> AlertExplanation:
        """Build guidance using only this template and caller-supplied evidence."""
        return AlertExplanation(
            rule_id=self.rule_id,
            title=self.title,
            summary=self.summary,
            why_it_matched=self.why_it_matched_template,
            possible_causes=list(self.possible_causes),
            recommended_actions=list(self.recommended_actions),
            evidence_summary=({} if evidence_summary is None else dict(evidence_summary)),
            confidence=self.confidence,
        )


EXPLANATION_TEMPLATES: dict[str, AlertExplanationTemplate] = {
    "AUTH-001": AlertExplanationTemplate(
        rule_id="AUTH-001",
        title="Failed SSH Login Attempt",
        summary="A failed SSH login attempt was observed and may require review.",
        why_it_matched_template=(
            "This alert was generated because an authentication event reported a failed SSH "
            "login attempt."
        ),
        possible_causes=[
            "mistyped password",
            "forgotten or unavailable account",
            "brute-force attempt",
            "automated login attempt",
        ],
        recommended_actions=[
            "review the source address",
            "check for repeated authentication failures",
            "confirm whether the username is valid and expected",
            "review related authentication logs",
        ],
        confidence="medium",
    ),
    "AUTH-002": AlertExplanationTemplate(
        rule_id="AUTH-002",
        title="Successful SSH Login",
        summary="A successful SSH login was observed and should be confirmed if unexpected.",
        why_it_matched_template=(
            "This alert was generated because an authentication event reported a successful "
            "SSH login."
        ),
        possible_causes=[
            "expected user or administrator access",
            "authorized automated maintenance",
            "an unfamiliar but authorized connection",
            "account activity requiring further review",
        ],
        recommended_actions=[
            "confirm that the login was expected",
            "review the username, source address, and login time",
            "compare the activity with approved access patterns",
            "inspect related authentication logs if the context is unusual",
        ],
        confidence="medium",
    ),
    "AUTH-003": AlertExplanationTemplate(
        rule_id="AUTH-003",
        title="Privileged Command Usage",
        summary="A sudo command execution event was observed and may require authorization review.",
        why_it_matched_template=(
            "This alert was generated because an authentication event reported sudo command usage."
        ),
        possible_causes=[
            "authorized administrative work",
            "software installation or maintenance",
            "an automated privileged task",
            "unexpected use of elevated privileges",
        ],
        recommended_actions=[
            "review the command and requesting user",
            "confirm that the privileged action was authorized",
            "check the working directory and execution time",
            "inspect related authentication and system logs",
        ],
        confidence="medium",
    ),
    "PROC-001": AlertExplanationTemplate(
        rule_id="PROC-001",
        title="Process Running From Temporary Path",
        summary="A process executable was observed in a commonly writable temporary path.",
        why_it_matched_template=(
            "This alert was generated because the observed executable path begins with a "
            "configured temporary directory."
        ),
        possible_causes=[
            "legitimate installer or update activity",
            "temporary development or administration work",
            "an application unpacking and running a helper process",
            "unexpected execution from a writable location",
        ],
        recommended_actions=[
            "review the executable path and command line",
            "confirm the process owner and origin",
            "check whether installation or maintenance activity was expected",
            "investigate related process and system logs",
        ],
        confidence="medium",
    ),
    "PROC-002": AlertExplanationTemplate(
        rule_id="PROC-002",
        title="High Process Resource Usage",
        summary="A process reached the configured CPU or memory usage threshold.",
        why_it_matched_template=(
            "This alert was generated because observed CPU or memory usage met or exceeded "
            "the configured threshold."
        ),
        possible_causes=[
            "expected computational workload",
            "temporary application demand",
            "software fault or inefficient processing",
            "an unexpected background task",
        ],
        recommended_actions=[
            "observe the process resource usage over time",
            "review the executable, user, and command line",
            "compare usage with the process's expected workload",
            "investigate related application and system logs",
        ],
        confidence="medium",
    ),
    "PROC-003": AlertExplanationTemplate(
        rule_id="PROC-003",
        title="Process Keyword Requires Review",
        summary="Process evidence contained a configured keyword that warrants investigation.",
        why_it_matched_template=(
            "This alert was generated because sanitized process name, path, or command-line "
            "evidence matched a configured keyword."
        ),
        possible_causes=[
            "authorized use of an administration or networking tool",
            "development or troubleshooting activity",
            "a coincidental keyword in legitimate process data",
            "unexpected tool execution requiring review",
        ],
        recommended_actions=[
            "review the complete available process context",
            "confirm whether the identified tool or behavior is authorized",
            "inspect the process owner, parent, path, and command line",
            "investigate related process and system activity",
        ],
        confidence="low",
    ),
    "NET-001": AlertExplanationTemplate(
        rule_id="NET-001",
        title="Listening Service on Unusual Port",
        summary="A listening network endpoint was observed outside the common-port set.",
        why_it_matched_template=(
            "This alert was generated because a listening endpoint used a valid local port "
            "that is not in the configured common-port set."
        ),
        possible_causes=[
            "an expected application-specific service",
            "a development or testing service",
            "a recently installed application",
            "an unexpected listening service",
        ],
        recommended_actions=[
            "confirm that the service and port are expected",
            "review the associated process and user",
            "check the intended network exposure",
            "investigate firewall configuration and related logs",
        ],
        confidence="medium",
    ),
    "NET-002": AlertExplanationTemplate(
        rule_id="NET-002",
        title="External Remote Connection",
        summary="A connection to a remote address outside local network ranges was observed.",
        why_it_matched_template=(
            "This alert was generated because the observed remote IP address was outside the "
            "configured local address ranges."
        ),
        possible_causes=[
            "expected internet service access",
            "software update or cloud service traffic",
            "remote administration activity",
            "an unfamiliar external connection requiring review",
        ],
        recommended_actions=[
            "review the remote address and port",
            "identify the associated process and user",
            "confirm that the destination fits the system's expected role",
            "inspect related network and application logs",
        ],
        confidence="medium",
    ),
    "NET-003": AlertExplanationTemplate(
        rule_id="NET-003",
        title="Remote Port Requires Review",
        summary="A connection used a remote port designated for additional investigation.",
        why_it_matched_template=(
            "This alert was generated because the observed remote port matched the configured "
            "investigation port set."
        ),
        possible_causes=[
            "an authorized service using the selected port",
            "development or testing traffic",
            "a custom application protocol",
            "unexpected network activity requiring review",
        ],
        recommended_actions=[
            "review the local and remote connection endpoints",
            "identify the associated process and user",
            "confirm whether use of the remote port is expected",
            "investigate related network and process logs",
        ],
        confidence="low",
    ),
    "FIM-001": AlertExplanationTemplate(
        rule_id="FIM-001",
        title="Monitored File Is Missing",
        summary="A selected file path was reported as absent during the observation.",
        why_it_matched_template=(
            "This alert was generated because the file integrity observation reported that "
            "the selected path does not exist."
        ),
        possible_causes=[
            "an incorrect or outdated path",
            "intentional file removal or relocation",
            "deployment or maintenance activity",
            "unexpected file removal",
        ],
        recommended_actions=[
            "confirm that the selected path is correct",
            "check whether the file was intentionally removed or moved",
            "review recent deployments and maintenance",
            "inspect related file and user activity",
        ],
        confidence="medium",
    ),
    "FIM-002": AlertExplanationTemplate(
        rule_id="FIM-002",
        title="File Integrity Check Error",
        summary="A file integrity observation reported a collection or inspection error.",
        why_it_matched_template=(
            "This alert was generated because the file integrity observation contained a "
            "non-empty error value."
        ),
        possible_causes=[
            "insufficient runtime permissions",
            "temporary path unavailability",
            "filesystem or input/output error",
            "a path changing during observation",
        ],
        recommended_actions=[
            "review the reported error and selected path",
            "confirm the runtime account has appropriate read access",
            "check current path and filesystem availability",
            "repeat the observation when appropriate",
        ],
        confidence="medium",
    ),
    "FIM-003": AlertExplanationTemplate(
        rule_id="FIM-003",
        title="Directory Supplied for File Check",
        summary="A selected path was a directory rather than a regular file.",
        why_it_matched_template=(
            "This alert was generated because the selected path existed but was not reported "
            "as a regular file."
        ),
        possible_causes=[
            "a directory was selected by mistake",
            "the monitored path changed type",
            "configuration points to a parent directory",
        ],
        recommended_actions=[
            "confirm that the intended path identifies a regular file",
            "review the file integrity monitoring configuration",
            "select individual files that require monitoring",
        ],
        confidence="high",
    ),
    "FIM-004": AlertExplanationTemplate(
        rule_id="FIM-004",
        title="File Changed Compared With Baseline",
        summary="A monitored file changed compared with the saved baseline.",
        why_it_matched_template=(
            "This alert was generated because the file integrity baseline comparison reported "
            "a changed file state."
        ),
        possible_causes=[
            "legitimate software update",
            "manual file edit",
            "deployment or configuration change",
            "unauthorized modification",
        ],
        recommended_actions=[
            "confirm whether the change was expected",
            "review recent system updates or deployments",
            "compare the file with a trusted version",
            "inspect related logs or user activity",
        ],
        confidence="high",
    ),
    "FIM-005": AlertExplanationTemplate(
        rule_id="FIM-005",
        title="File Missing Compared With Baseline",
        summary="A file recorded in the baseline was absent from the current observation.",
        why_it_matched_template=(
            "This alert was generated because the baseline comparison reported that a "
            "previously observed file is now missing."
        ),
        possible_causes=[
            "intentional removal, move, or rename",
            "software update or deployment",
            "storage or mount availability issue",
            "unexpected file removal",
        ],
        recommended_actions=[
            "confirm whether the file was intentionally removed or relocated",
            "review recent deployments and maintenance",
            "check path and storage availability",
            "investigate related file and user activity",
        ],
        confidence="high",
    ),
    "FIM-006": AlertExplanationTemplate(
        rule_id="FIM-006",
        title="File Appeared Compared With Baseline",
        summary="A file absent from the baseline was present in the current observation.",
        why_it_matched_template=(
            "This alert was generated because the baseline comparison reported that a "
            "previously absent file is now present."
        ),
        possible_causes=[
            "authorized file creation",
            "software installation or deployment",
            "restoration of a previously missing file",
            "unexpected file creation",
        ],
        recommended_actions=[
            "confirm whether the file creation was expected",
            "review recent application and deployment activity",
            "compare the file with an approved source when available",
            "inspect related file and user activity",
        ],
        confidence="high",
    ),
    "FIM-007": AlertExplanationTemplate(
        rule_id="FIM-007",
        title="File Type Changed Compared With Baseline",
        summary="A monitored path's type differed from its saved baseline entry.",
        why_it_matched_template=(
            "This alert was generated because the baseline comparison reported a change in "
            "the monitored path type."
        ),
        possible_causes=[
            "intentional replacement of a file with a directory",
            "deployment or configuration change",
            "path redirection or link changes",
            "unexpected replacement of the monitored path",
        ],
        recommended_actions=[
            "confirm whether the path type change was expected",
            "review recent deployments and configuration changes",
            "inspect the current path and its ownership",
            "compare the path with the approved system state",
        ],
        confidence="high",
    ),
    "FIM-008": AlertExplanationTemplate(
        rule_id="FIM-008",
        title="Baseline Comparison Error",
        summary="A current file observation reported an error during baseline comparison.",
        why_it_matched_template=(
            "This alert was generated because the baseline comparison reported an error for "
            "the current file observation."
        ),
        possible_causes=[
            "insufficient runtime permissions",
            "temporary path or storage unavailability",
            "filesystem or input/output error",
            "a path changing during comparison",
        ],
        recommended_actions=[
            "review the reported comparison error",
            "confirm runtime permissions and path availability",
            "check filesystem and storage status",
            "repeat the observation when appropriate",
        ],
        confidence="medium",
    ),
}


def get_explanation_template(rule_id: str) -> AlertExplanationTemplate | None:
    """Return the deterministic template for a known rule ID, if available."""
    return EXPLANATION_TEMPLATES.get(rule_id)


def build_generic_explanation(
    rule_id: str,
    evidence_summary: Mapping[str, object] | None = None,
) -> AlertExplanation:
    """Build cautious guidance without assigning meaning to an unknown rule."""
    return AlertExplanation(
        rule_id=rule_id,
        title="General Alert Explanation",
        summary="No specific deterministic template exists for this rule.",
        why_it_matched=(
            "This general explanation was created because no matching rule template was available."
        ),
        possible_causes=[],
        recommended_actions=[
            "review the rule match",
            "review the supplied evidence",
            "inspect related logs",
            "consider the wider system context",
        ],
        evidence_summary={} if evidence_summary is None else dict(evidence_summary),
        confidence="low",
    )
