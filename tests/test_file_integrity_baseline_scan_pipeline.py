from pathlib import Path

import pytest

from sentinellite.baseline.file_integrity import (
    BASELINE_VERSION,
    FileIntegrityBaseline,
    FileIntegrityBaselineEntry,
    load_baseline,
    save_baseline,
)
from sentinellite.collectors.file_integrity import FileIntegrityRecord
from sentinellite.pipeline.file_integrity_baseline_scan import (
    FileIntegrityBaselineCreateSummary,
    FileIntegrityBaselineScanSummary,
    create_file_integrity_baseline,
    run_file_integrity_baseline_scan,
)
from sentinellite.reporting.json_reporter import read_alert_report


def create_entry(path: str) -> FileIntegrityBaselineEntry:
    return FileIntegrityBaselineEntry(
        path=path,
        exists=True,
        is_file=True,
        size_bytes=8,
        modified_time_epoch=1_700_000_000.0,
        sha256="a" * 64,
        error=None,
    )


def create_record(path: str) -> FileIntegrityRecord:
    entry = create_entry(path)
    return FileIntegrityRecord(
        path=entry.path,
        exists=entry.exists,
        is_file=entry.is_file,
        size_bytes=entry.size_bytes,
        modified_time_epoch=entry.modified_time_epoch,
        sha256=entry.sha256,
        error=entry.error,
    )


def save_test_baseline(
    baseline_path: Path,
    paths: list[str],
) -> FileIntegrityBaseline:
    baseline = FileIntegrityBaseline(
        version=BASELINE_VERSION,
        created_at="2026-08-19T10:30:00+00:00",
        entries=[create_entry(path) for path in paths],
    )
    save_baseline(baseline, baseline_path)
    return baseline


def test_create_file_integrity_baseline_writes_json_and_returns_counts(
    tmp_path: Path,
) -> None:
    monitored_path = tmp_path / "monitored.txt"
    monitored_path.write_text("observed content", encoding="utf-8")
    missing_path = tmp_path / "missing.txt"
    baseline_path = tmp_path / "baseline.json"

    summary = create_file_integrity_baseline(
        [str(monitored_path), str(missing_path)],
        baseline_path,
    )

    assert isinstance(summary, FileIntegrityBaselineCreateSummary)
    assert summary.files_checked_count == 2
    assert summary.baseline_entries_count == 2
    assert summary.baseline_path == baseline_path
    assert baseline_path.exists()


def test_saved_baseline_contains_expected_entries(tmp_path: Path) -> None:
    first_path = tmp_path / "first.txt"
    second_path = tmp_path / "second.txt"
    first_path.write_text("first", encoding="utf-8")
    second_path.write_text("second", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"

    create_file_integrity_baseline(
        [str(second_path), str(first_path)],
        baseline_path,
    )

    baseline = load_baseline(baseline_path)
    assert [entry.path for entry in baseline.entries] == [str(second_path), str(first_path)]
    assert all(entry.exists and entry.is_file for entry in baseline.entries)
    assert all(entry.sha256 is not None for entry in baseline.entries)


def test_baseline_scan_detects_changed_file_and_writes_report(tmp_path: Path) -> None:
    monitored_path = tmp_path / "monitored.txt"
    monitored_path.write_text("original", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_file_integrity_baseline([str(monitored_path)], baseline_path)
    monitored_path.write_text("updated content", encoding="utf-8")

    summary = run_file_integrity_baseline_scan(
        baseline_path,
        output_dir=tmp_path / "reports",
    )

    assert isinstance(summary, FileIntegrityBaselineScanSummary)
    assert summary.baseline_path == baseline_path
    assert summary.files_checked_count == 1
    assert summary.comparisons_count == 1
    assert summary.security_events_count == 1
    assert summary.detection_matches_count == 1
    assert summary.scored_alerts_count == 1
    assert summary.report_path.exists()
    report = read_alert_report(summary.report_path)
    assert report["alert_count"] == 1
    assert report["alerts"][0]["rule_id"] == "FIM-004"
    assert report["alerts"][0]["risk_score"] == 70


def test_unchanged_file_produces_zero_scored_alerts(tmp_path: Path) -> None:
    monitored_path = tmp_path / "unchanged.txt"
    monitored_path.write_text("unchanged", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_file_integrity_baseline([str(monitored_path)], baseline_path)

    summary = run_file_integrity_baseline_scan(
        baseline_path,
        output_dir=tmp_path / "reports",
    )

    assert summary.files_checked_count == 1
    assert summary.comparisons_count == 1
    assert summary.security_events_count == 1
    assert summary.detection_matches_count == 0
    assert summary.scored_alerts_count == 0
    report = read_alert_report(summary.report_path)
    assert report["alert_count"] == 0
    assert report["alerts"] == []


def test_missing_file_compared_with_baseline_produces_alert(tmp_path: Path) -> None:
    monitored_path = tmp_path / "removed.txt"
    monitored_path.write_text("present during baseline", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_file_integrity_baseline([str(monitored_path)], baseline_path)
    monitored_path.unlink()

    summary = run_file_integrity_baseline_scan(
        baseline_path,
        output_dir=tmp_path / "reports",
    )

    assert summary.detection_matches_count == 1
    assert summary.scored_alerts_count == 1
    report = read_alert_report(summary.report_path)
    rule_ids = [alert["rule_id"] for alert in report["alerts"]]
    assert rule_ids == ["FIM-005"]
    assert "FIM-008" not in rule_ids


def test_baseline_scan_preserves_baseline_path_order(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected_paths = [
        str(tmp_path / "third.txt"),
        str(tmp_path / "first.txt"),
        str(tmp_path / "second.txt"),
    ]
    baseline_path = tmp_path / "baseline.json"
    save_test_baseline(baseline_path, expected_paths)
    observed_paths: list[str] = []

    def fake_collect_file_integrity(paths) -> list[FileIntegrityRecord]:
        observed_paths.extend(paths)
        return [create_record(path) for path in paths]

    monkeypatch.setattr(
        "sentinellite.pipeline.file_integrity_baseline_scan.collect_file_integrity",
        fake_collect_file_integrity,
    )

    run_file_integrity_baseline_scan(baseline_path, output_dir=tmp_path / "reports")

    assert observed_paths == expected_paths


def test_baseline_scan_uses_only_paths_from_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monitored_path = str(tmp_path / "monitored.txt")
    unrelated_path = tmp_path / "unrelated.txt"
    unrelated_path.write_text("must not be scanned", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    save_test_baseline(baseline_path, [monitored_path])
    collected_paths: list[str] = []

    def fake_collect_file_integrity(paths) -> list[FileIntegrityRecord]:
        collected_paths.extend(paths)
        return [create_record(path) for path in paths]

    monkeypatch.setattr(
        "sentinellite.pipeline.file_integrity_baseline_scan.collect_file_integrity",
        fake_collect_file_integrity,
    )

    run_file_integrity_baseline_scan(baseline_path, output_dir=tmp_path / "reports")

    assert collected_paths == [monitored_path]
    assert str(unrelated_path) not in collected_paths


def test_missing_baseline_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_file_integrity_baseline_scan(
            tmp_path / "missing-baseline.json",
            output_dir=tmp_path / "reports",
        )


def test_create_and_scan_do_not_modify_monitored_files(tmp_path: Path) -> None:
    monitored_path = tmp_path / "monitored.txt"
    monitored_path.write_text("original content", encoding="utf-8")
    missing_path = tmp_path / "missing.txt"
    original_stat = monitored_path.stat()
    baseline_path = tmp_path / "baseline.json"

    create_file_integrity_baseline(
        [str(monitored_path), str(missing_path)],
        baseline_path,
    )
    run_file_integrity_baseline_scan(
        baseline_path,
        output_dir=tmp_path / "reports",
    )

    assert monitored_path.read_text(encoding="utf-8") == "original content"
    current_stat = monitored_path.stat()
    assert current_stat.st_size == original_stat.st_size
    assert current_stat.st_mtime_ns == original_stat.st_mtime_ns
    assert current_stat.st_mode == original_stat.st_mode
    assert not missing_path.exists()
