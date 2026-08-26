from pathlib import Path

import pytest

from sentinellite.collectors.network import NetworkConnection
from sentinellite.pipeline.network_scan import NetworkScanSummary, run_network_scan
from sentinellite.reporting.json_reporter import read_alert_report


def create_connection(
    *,
    fd: int,
    local_port: int,
    remote_address: str | None,
    remote_port: int | None,
    status: str,
) -> NetworkConnection:
    return NetworkConnection(
        fd=fd,
        family=2,
        type=1,
        local_address="127.0.0.1",
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        status=status,
        pid=4242,
        process_name="worker",
    )


def test_network_scan_writes_scored_network_alert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    connections = [
        create_connection(
            fd=7,
            local_port=22,
            remote_address=None,
            remote_port=None,
            status="LISTEN",
        ),
        create_connection(
            fd=8,
            local_port=8080,
            remote_address=None,
            remote_port=None,
            status="LISTEN",
        ),
    ]
    monkeypatch.setattr(
        "sentinellite.pipeline.network_scan.collect_network_connections",
        lambda: connections,
    )

    summary = run_network_scan(output_dir=tmp_path)

    assert isinstance(summary, NetworkScanSummary)
    assert summary.connections_count == 2
    assert summary.security_events_count == 2
    assert summary.detection_matches_count == 1
    assert summary.scored_alerts_count == 1

    report_path = Path(summary.report_path)
    assert report_path.exists()

    report_data = read_alert_report(report_path)
    assert report_data["alert_count"] == 1
    assert report_data["alerts"][0]["rule_id"] == "NET-001"
    assert report_data["alerts"][0]["risk_score"] == 55
    assert report_data["alerts"][0]["risk_level"] == "medium"
    assert "explanation" not in report_data["alerts"][0]
    assert "explanations" not in report_data

    assert summary.to_dict() == {
        "connections_count": 2,
        "security_events_count": 2,
        "detection_matches_count": 1,
        "scored_alerts_count": 1,
        "report_path": str(report_path),
    }


def test_network_scan_includes_explanation_when_requested(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "sentinellite.pipeline.network_scan.collect_network_connections",
        lambda: [
            create_connection(
                fd=8,
                local_port=8080,
                remote_address=None,
                remote_port=None,
                status="LISTEN",
            )
        ],
    )

    summary = run_network_scan(output_dir=tmp_path, include_explanations=True)
    report_data = read_alert_report(summary.report_path)

    alert = report_data["alerts"][0]
    assert alert["rule_id"] == "NET-001"
    assert alert["explanation"]["rule_id"] == "NET-001"
    assert "explanations" not in report_data


def test_network_scan_writes_empty_report_when_no_rules_match(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    connections = [
        create_connection(
            fd=7,
            local_port=5000,
            remote_address="192.168.1.20",
            remote_port=443,
            status="ESTABLISHED",
        )
    ]
    monkeypatch.setattr(
        "sentinellite.pipeline.network_scan.collect_network_connections",
        lambda: connections,
    )

    summary = run_network_scan(output_dir=tmp_path, include_explanations=True)

    assert summary.connections_count == 1
    assert summary.security_events_count == 1
    assert summary.detection_matches_count == 0
    assert summary.scored_alerts_count == 0

    report_path = Path(summary.report_path)
    assert report_path.exists()

    report_data = read_alert_report(report_path)
    assert report_data["alert_count"] == 0
    assert report_data["alerts"] == []
    assert "explanations" not in report_data
    assert "explanation" not in report_data
