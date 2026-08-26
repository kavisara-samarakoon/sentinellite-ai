from pathlib import Path

import pytest

from sentinellite.collectors.file_integrity import FileIntegrityRecord
from sentinellite.detection.rules import active_rules_from_disabled_ids
from sentinellite.pipeline.file_integrity_scan import (
    FileIntegrityScanSummary,
    run_file_integrity_scan,
)
from sentinellite.reporting.json_reporter import read_alert_report


def create_normal_record(path: str = "/selected/config.txt") -> FileIntegrityRecord:
    return FileIntegrityRecord(
        path=path,
        exists=True,
        is_file=True,
        size_bytes=128,
        modified_time_epoch=1_725_000_000.5,
        sha256="a" * 64,
        error=None,
    )


def test_file_integrity_scan_writes_scored_missing_file_alert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monitored_paths = [Path("/selected/config.txt"), "/selected/missing.txt"]
    records = [
        create_normal_record(),
        FileIntegrityRecord(
            path="/selected/missing.txt",
            exists=False,
            is_file=False,
            size_bytes=None,
            modified_time_epoch=None,
            sha256=None,
            error="Path does not exist: /selected/missing.txt",
        ),
    ]

    def fake_collect_file_integrity(paths) -> list[FileIntegrityRecord]:
        assert paths == monitored_paths
        return records

    monkeypatch.setattr(
        "sentinellite.pipeline.file_integrity_scan.collect_file_integrity",
        fake_collect_file_integrity,
    )

    summary = run_file_integrity_scan(monitored_paths, output_dir=tmp_path)

    assert isinstance(summary, FileIntegrityScanSummary)
    assert summary.files_checked_count == 2
    assert summary.security_events_count == 2
    assert summary.detection_matches_count == 2
    assert summary.scored_alerts_count == 2

    report_path = Path(summary.report_path)
    assert report_path.exists()

    report_data = read_alert_report(report_path)
    assert report_data["alert_count"] == 2
    assert [alert["rule_id"] for alert in report_data["alerts"]] == [
        "FIM-001",
        "FIM-002",
    ]
    missing_file_alert = report_data["alerts"][0]
    assert missing_file_alert["risk_score"] == 60
    assert missing_file_alert["risk_level"] == "medium"
    assert all("explanation" not in alert for alert in report_data["alerts"])
    assert "explanations" not in report_data

    assert summary.to_dict() == {
        "files_checked_count": 2,
        "security_events_count": 2,
        "detection_matches_count": 2,
        "scored_alerts_count": 2,
        "report_path": str(report_path),
    }


def test_file_integrity_scan_includes_explanations_when_requested(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monitored_paths = ["/selected/missing.txt"]
    monkeypatch.setattr(
        "sentinellite.pipeline.file_integrity_scan.collect_file_integrity",
        lambda paths: [
            FileIntegrityRecord(
                path="/selected/missing.txt",
                exists=False,
                is_file=False,
                size_bytes=None,
                modified_time_epoch=None,
                sha256=None,
                error="Path does not exist: /selected/missing.txt",
            )
        ],
    )

    summary = run_file_integrity_scan(
        monitored_paths,
        output_dir=tmp_path,
        include_explanations=True,
    )
    report_data = read_alert_report(summary.report_path)

    assert [alert["rule_id"] for alert in report_data["alerts"]] == [
        "FIM-001",
        "FIM-002",
    ]
    assert all("explanation" in alert for alert in report_data["alerts"])
    assert all(
        alert["explanation"]["rule_id"] == alert["rule_id"]
        for alert in report_data["alerts"]
    )
    assert "explanations" not in report_data


def test_file_integrity_scan_can_disable_only_missing_file_rule(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monitored_paths = ["/selected/missing.txt"]
    monkeypatch.setattr(
        "sentinellite.pipeline.file_integrity_scan.collect_file_integrity",
        lambda paths: [
            FileIntegrityRecord(
                path="/selected/missing.txt",
                exists=False,
                is_file=False,
                size_bytes=None,
                modified_time_epoch=None,
                sha256=None,
                error="Path does not exist: /selected/missing.txt",
            )
        ],
    )
    rules = active_rules_from_disabled_ids(["FIM-001"])

    summary = run_file_integrity_scan(
        monitored_paths,
        output_dir=tmp_path,
        rules=rules,
    )

    assert summary.detection_matches_count == 1
    assert summary.scored_alerts_count == 1
    report_data = read_alert_report(summary.report_path)
    assert [alert["rule_id"] for alert in report_data["alerts"]] == ["FIM-002"]
    assert "explanations" not in report_data


def test_file_integrity_scan_writes_empty_report_when_no_rules_match(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monitored_paths = ["/selected/config.txt"]
    records = [create_normal_record()]

    monkeypatch.setattr(
        "sentinellite.pipeline.file_integrity_scan.collect_file_integrity",
        lambda paths: records,
    )

    summary = run_file_integrity_scan(
        monitored_paths,
        output_dir=tmp_path,
        include_explanations=True,
    )

    assert summary.files_checked_count == 1
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
