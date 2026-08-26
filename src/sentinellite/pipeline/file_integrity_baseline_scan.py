from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinellite.baseline.file_integrity import (
    compare_records_to_baseline,
    create_baseline_from_records,
    load_baseline,
    save_baseline,
)
from sentinellite.collectors.file_integrity import collect_file_integrity
from sentinellite.detection.engine import detect_events
from sentinellite.detection.rules import DetectionRule
from sentinellite.normalization.file_integrity_baseline import (
    file_integrity_baseline_comparison_to_security_event,
)
from sentinellite.reporting.json_reporter import write_alert_report
from sentinellite.scoring.risk import score_rule_matches


@dataclass(frozen=True, slots=True)
class FileIntegrityBaselineCreateSummary:
    files_checked_count: int
    baseline_entries_count: int
    baseline_path: Path


def create_file_integrity_baseline(
    paths: Sequence[str],
    baseline_path: Path | str,
) -> FileIntegrityBaselineCreateSummary:
    """Collect explicitly selected paths and save their baseline observations."""
    records = collect_file_integrity(paths)
    baseline = create_baseline_from_records(records)
    written_baseline_path = save_baseline(baseline, baseline_path)

    return FileIntegrityBaselineCreateSummary(
        files_checked_count=len(records),
        baseline_entries_count=len(baseline.entries),
        baseline_path=written_baseline_path,
    )


@dataclass(frozen=True, slots=True)
class FileIntegrityBaselineScanSummary:
    baseline_path: Path
    files_checked_count: int
    comparisons_count: int
    security_events_count: int
    detection_matches_count: int
    scored_alerts_count: int
    report_path: Path


def run_file_integrity_baseline_scan(
    baseline_path: Path | str,
    output_dir: Path | str = "reports",
    *,
    include_explanations: bool = False,
    rules: Sequence[DetectionRule] | None = None,
) -> FileIntegrityBaselineScanSummary:
    """Compare current observations with a saved baseline and report scored alerts."""
    loaded_baseline_path = Path(baseline_path)
    baseline = load_baseline(loaded_baseline_path)
    monitored_paths = [entry.path for entry in baseline.entries]

    records = collect_file_integrity(monitored_paths)
    comparisons = compare_records_to_baseline(records, baseline)
    security_events = [
        file_integrity_baseline_comparison_to_security_event(comparison)
        for comparison in comparisons
    ]
    detection_matches = detect_events(security_events, rules=rules)
    scored_alerts = score_rule_matches(detection_matches)
    report_path = write_alert_report(
        scored_alerts,
        output_dir=output_dir,
        include_explanations=include_explanations,
    )

    return FileIntegrityBaselineScanSummary(
        baseline_path=loaded_baseline_path,
        files_checked_count=len(records),
        comparisons_count=len(comparisons),
        security_events_count=len(security_events),
        detection_matches_count=len(detection_matches),
        scored_alerts_count=len(scored_alerts),
        report_path=report_path,
    )
