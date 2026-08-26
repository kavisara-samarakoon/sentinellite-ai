from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from sentinellite.collectors.file_integrity import collect_file_integrity
from sentinellite.detection.engine import detect_events
from sentinellite.detection.rules import DetectionRule
from sentinellite.normalization.file_integrity import (
    file_integrity_record_to_security_event,
)
from sentinellite.reporting.json_reporter import write_alert_report
from sentinellite.scoring.risk import score_rule_matches


@dataclass(frozen=True)
class FileIntegrityScanSummary:
    files_checked_count: int
    security_events_count: int
    detection_matches_count: int
    scored_alerts_count: int
    report_path: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def run_file_integrity_scan(
    paths: Sequence[Path | str],
    output_dir: Path | str = "reports",
    *,
    include_explanations: bool = False,
    rules: Sequence[DetectionRule] | None = None,
) -> FileIntegrityScanSummary:
    """Observe selected file paths and write scored detection alerts to JSON."""
    records = collect_file_integrity(paths)

    security_events = [
        file_integrity_record_to_security_event(record)
        for record in records
    ]

    detection_matches = detect_events(security_events, rules=rules)
    scored_alerts = score_rule_matches(detection_matches)

    report_path = write_alert_report(
        scored_alerts,
        output_dir=output_dir,
        include_explanations=include_explanations,
    )

    return FileIntegrityScanSummary(
        files_checked_count=len(records),
        security_events_count=len(security_events),
        detection_matches_count=len(detection_matches),
        scored_alerts_count=len(scored_alerts),
        report_path=str(report_path),
    )
