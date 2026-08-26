from dataclasses import asdict, dataclass
from pathlib import Path

from sentinellite.collectors.network import collect_network_connections
from sentinellite.detection.engine import detect_events
from sentinellite.normalization.network import network_connection_to_security_event
from sentinellite.reporting.json_reporter import write_alert_report
from sentinellite.scoring.risk import score_rule_matches


@dataclass(frozen=True)
class NetworkScanSummary:
    connections_count: int
    security_events_count: int
    detection_matches_count: int
    scored_alerts_count: int
    report_path: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def run_network_scan(
    output_dir: Path | str = "reports",
    *,
    include_explanations: bool = False,
) -> NetworkScanSummary:
    """Collect network observations and write scored detection alerts to JSON."""
    connections = collect_network_connections()

    security_events = [
        network_connection_to_security_event(connection)
        for connection in connections
    ]

    detection_matches = detect_events(security_events)
    scored_alerts = score_rule_matches(detection_matches)

    report_path = write_alert_report(
        scored_alerts,
        output_dir=output_dir,
        include_explanations=include_explanations,
    )

    return NetworkScanSummary(
        connections_count=len(connections),
        security_events_count=len(security_events),
        detection_matches_count=len(detection_matches),
        scored_alerts_count=len(scored_alerts),
        report_path=str(report_path),
    )
