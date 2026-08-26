from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from sentinellite.collectors.auth import (
    auth_event_to_security_event,
    collect_auth_events_from_file,
)
from sentinellite.detection.engine import detect_events
from sentinellite.detection.rules import DetectionRule
from sentinellite.reporting.json_reporter import write_alert_report
from sentinellite.scoring.risk import ScoredAlert, score_rule_matches


@dataclass(frozen=True)
class AuthScanSummary:
    log_path: str
    auth_events_count: int
    security_events_count: int
    detection_matches_count: int
    scored_alerts_count: int
    report_path: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def run_auth_scan(
    log_path: str | Path,
    output_dir: str | Path = "reports",
    report_filename: str | None = None,
    *,
    include_explanations: bool = False,
    rules: Sequence[DetectionRule] | None = None,
) -> tuple[AuthScanSummary, list[ScoredAlert]]:
    auth_events = collect_auth_events_from_file(log_path)

    security_events = [
        auth_event_to_security_event(auth_event)
        for auth_event in auth_events
    ]

    detection_matches = detect_events(security_events, rules=rules)
    scored_alerts = score_rule_matches(detection_matches)

    report_path = write_alert_report(
        scored_alerts,
        output_dir=output_dir,
        filename=report_filename,
        include_explanations=include_explanations,
    )

    summary = AuthScanSummary(
        log_path=str(log_path),
        auth_events_count=len(auth_events),
        security_events_count=len(security_events),
        detection_matches_count=len(detection_matches),
        scored_alerts_count=len(scored_alerts),
        report_path=str(report_path),
    )

    return summary, scored_alerts
