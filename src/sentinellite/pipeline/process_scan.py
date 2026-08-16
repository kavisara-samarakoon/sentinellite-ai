from dataclasses import asdict, dataclass
from pathlib import Path

from sentinellite.collectors.process import collect_processes
from sentinellite.detection.engine import detect_events
from sentinellite.normalization.process import process_to_security_event
from sentinellite.reporting.json_reporter import write_alert_report
from sentinellite.scoring.risk import score_rule_matches


@dataclass(frozen=True)
class ProcessScanSummary:
    processes_count: int
    security_events_count: int
    detection_matches_count: int
    scored_alerts_count: int
    report_path: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def run_process_scan(output_dir: Path | str = "reports") -> ProcessScanSummary:
    """Collect process observations and write scored detection alerts to JSON."""
    processes = collect_processes()

    security_events = [
        process_to_security_event(process)
        for process in processes
    ]

    detection_matches = detect_events(security_events)
    scored_alerts = score_rule_matches(detection_matches)

    report_path = write_alert_report(
        scored_alerts,
        output_dir=output_dir,
    )

    return ProcessScanSummary(
        processes_count=len(processes),
        security_events_count=len(security_events),
        detection_matches_count=len(detection_matches),
        scored_alerts_count=len(scored_alerts),
        report_path=str(report_path),
    )
