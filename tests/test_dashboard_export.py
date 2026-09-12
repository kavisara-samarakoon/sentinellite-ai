import json
import os
from html import escape
from html.parser import HTMLParser
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinellite.main import app
from sentinellite.pipeline.demo import run_demo
from sentinellite.reporting.dashboard import (
    SAFETY_BANNER,
    DashboardExportError,
    export_dashboard,
    load_dashboard_data,
)
from sentinellite.reporting.review import MAX_REPORT_SIZE_BYTES

runner = CliRunner()


def write_report(
    directory: Path,
    name: str = "report.json",
    *,
    generated_at: object = "2026-09-12T12:00:00Z",
    alerts: list[dict] | None = None,
) -> Path:
    if alerts is None:
        alerts = [
            {
                "rule_id": "AUTH-001",
                "rule_name": "Failed SSH Login",
                "severity": "medium",
                "category": "authentication",
                "source": "sshd",
                "risk_score": 50,
                "message": "Synthetic authentication example",
            }
        ]
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(
        json.dumps(
            {
                "report_id": "local-report",
                "report_type": "sentinellite_alert_report",
                "generated_at": generated_at,
                "alert_count": len(alerts),
                "alerts": alerts,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_export_without_reports_creates_parent_and_empty_dashboard(tmp_path: Path) -> None:
    reports_dir = tmp_path / "missing-reports"
    output = tmp_path / "output" / "nested" / "dashboard.html"

    assert export_dashboard(reports_dir, output) == output

    document = output.read_text(encoding="utf-8")
    assert "SentinelLite AI Local Dashboard" in document
    assert SAFETY_BANNER in document
    assert "No reports were found" in document
    assert "No alerts to display" in document
    assert "Showing 0 of 0 loaded reports" in document
    assert "Generated from local SentinelLite AI JSON reports." in document
    assert not reports_dir.exists()


def test_valid_demo_report_exports_summary_without_evidence_or_report_changes(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    summary, _ = run_demo(reports_dir, include_explanations=True)
    path = Path(summary.report_path)
    report = json.loads(path.read_text(encoding="utf-8"))
    for alert in report["alerts"]:
        alert["evidence"]["private"] = "EVIDENCE_MUST_NOT_APPEAR"
        alert["explanation"]["evidence_summary"] = {"private": "NESTED_EVIDENCE_MUST_NOT_APPEAR"}
        alert["raw_data"] = "RAW_DATA_MUST_NOT_APPEAR"
    path.write_text(json.dumps(report), encoding="utf-8")
    original = path.read_bytes()
    output = reports_dir / "dashboard.html"

    export_dashboard(reports_dir, output)

    document = output.read_text(encoding="utf-8")
    assert path.read_bytes() == original
    for expected in (
        "SentinelLite AI Local Dashboard",
        SAFETY_BANNER,
        "BETA",
        "Total reports loaded",
        "Total alerts shown",
        "Highest severity shown",
        "Latest report time (UTC)",
        "Severity counts",
        "Rule counts",
        "Module counts",
        "Latest alerts",
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "authentication",
        "sshd",
        "Showing 1 of 1 loaded reports",
    ):
        assert expected in document
    assert escape(report["alerts"][0]["rule_name"], quote=True) in document
    assert escape(report["alerts"][0]["explanation"]["summary"], quote=True) in document
    assert "EVIDENCE_MUST_NOT_APPEAR" not in document
    assert "RAW_DATA_MUST_NOT_APPEAR" not in document
    assert len(load_dashboard_data(reports_dir).alerts) == 3


@pytest.mark.parametrize(
    "invalid",
    [
        b"{invalid json",
        b"\xff\xfe",
        b"[]",
        b"{}",
        b'{"report_type": "sentinellite_notification_summary", "alerts": []}',
        b'{"report_type": "sentinellite_alert_report", "alerts": [42]}',
        b'{"report_type": "sentinellite_alert_report", "alerts": [], "alert_count": 2}',
        b"[" * 1500 + b"]" * 1500,
        b'{"huge_number": ' + b"1" * 5000 + b"}",
    ],
)
def test_invalid_reports_are_skipped_without_hiding_valid_reports(
    tmp_path: Path,
    invalid: bytes,
) -> None:
    write_report(tmp_path)
    bad_path = tmp_path / "invalid.json"
    bad_path.write_bytes(invalid)

    export_dashboard(tmp_path, tmp_path / "dashboard.html")

    document = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert "AUTH-001" in document
    assert "Skipped files: 1" in document
    assert bad_path.read_bytes() == invalid


def test_all_invalid_reports_still_export_an_empty_dashboard(tmp_path: Path) -> None:
    (tmp_path / "invalid.json").write_text("bad data", encoding="utf-8")

    export_dashboard(tmp_path, tmp_path / "dashboard.html")

    document = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert "No valid reports are available" in document
    assert "Skipped files: 1" in document


def test_large_unreadable_and_non_regular_inputs_are_skipped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from sentinellite.reporting import dashboard

    write_report(tmp_path)
    large_path = tmp_path / "large.json"
    with large_path.open("wb") as stream:
        stream.truncate(MAX_REPORT_SIZE_BYTES + 1)
    unreadable = write_report(tmp_path, "unreadable.json")
    (tmp_path / "linked.json").symlink_to(tmp_path / "report.json")
    (tmp_path / "nested.json").mkdir()
    write_report(tmp_path / "nested.json", "nested.json")
    (tmp_path / "ignored.txt").write_text("not a report", encoding="utf-8")
    original_open = dashboard.os.open

    def guarded_open(path, *args, **kwargs):
        assert Path(path).name != "linked.json"
        if Path(path) == unreadable:
            raise PermissionError("simulated unreadable report")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(dashboard.os, "open", guarded_open)

    data = load_dashboard_data(tmp_path)

    assert data.reports_loaded == 1
    assert data.reports_skipped == 2
    assert len(data.alerts) == 1


def test_report_and_alert_limits_apply_after_newest_first_sorting(tmp_path: Path) -> None:
    write_report(
        tmp_path,
        "a-old.json",
        generated_at="2026-09-10T10:00:00Z",
        alerts=[{"title": "OLD_HIDDEN"}],
    )
    write_report(
        tmp_path,
        "b-middle.json",
        generated_at="2026-09-11T12:00:00Z",
        alerts=[{"title": "MIDDLE_HIDDEN", "severity": "critical"}],
    )
    write_report(
        tmp_path,
        "z-new.json",
        generated_at="2026-09-11T14:00:00+01:00",
        alerts=[
            {"title": "FIRST_SHOWN", "severity": "low", "timestamp": "2026-09-12T12:00:00Z"},
            {"title": "THIRD_HIDDEN", "severity": "critical"},
            {"title": "SECOND_SHOWN", "severity": "medium", "timestamp": "2026-09-12T11:00:00Z"},
        ],
    )
    write_report(tmp_path, "undated.json", generated_at=None, alerts=[{"title": "UNDATED_HIDDEN"}])

    data = load_dashboard_data(tmp_path, limit=2)
    export_dashboard(tmp_path, tmp_path / "dashboard.html", limit=2)

    assert data.reports_loaded == 4
    assert [report.filename for report in data.reports] == ["z-new.json", "b-middle.json"]
    assert [alert.title for alert in data.alerts] == ["FIRST_SHOWN", "SECOND_SHOWN"]
    document = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert "Showing 2 of 4 loaded reports" in document
    for hidden in ("OLD_HIDDEN", "MIDDLE_HIDDEN", "THIRD_HIDDEN", "UNDATED_HIDDEN", "a-old.json"):
        assert hidden not in document
    assert 'Highest severity shown</span><strong class="">medium</strong>' in document
    assert "2026-09-11T13:00:00Z" in document


def test_reports_with_no_alerts_are_loaded(tmp_path: Path) -> None:
    write_report(tmp_path, alerts=[])

    export_dashboard(tmp_path, tmp_path / "dashboard.html")

    document = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert "Showing 1 of 1 loaded reports" in document
    assert "No alerts to display" in document
    assert 'Highest severity shown</span><strong class="">None</strong>' in document


@pytest.mark.parametrize("generated_at", [None, "bad timestamp", "2026-09-12T12:00:00"])
def test_missing_optional_fields_and_unavailable_dates_are_safe(
    tmp_path: Path,
    generated_at: object,
) -> None:
    write_report(tmp_path, generated_at=generated_at, alerts=[{"title": "Minimal example"}])

    export_dashboard(tmp_path, tmp_path / "dashboard.html")

    document = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert "Minimal example" in document
    assert "Unavailable" in document
    assert '<span class="badge unknown">unknown</span>' in document
    assert "—" in document


class DashboardParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


def test_report_text_is_escaped_and_no_active_or_external_content_is_generated(
    tmp_path: Path,
) -> None:
    malicious = '<script>alert(1)</script> " onmouseover="evil & more'
    report = write_report(
        tmp_path,
        "<img src=x onerror=evil>.json",
        alerts=[
            {
                "severity": malicious,
                "rule_id": malicious,
                "rule_name": malicious,
                "source": malicious,
                "module": malicious,
                "risk_score": malicious,
                "explanation": {"summary": malicious},
                "evidence": {"private": "NEVER_RENDER_EVIDENCE"},
            }
        ],
    )

    export_dashboard(tmp_path, tmp_path / "dashboard.html")

    document = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert escape(malicious, quote=True) in document
    assert escape(report.name, quote=True) in document
    assert malicious not in document
    assert "NEVER_RENDER_EVIDENCE" not in document
    parsed = DashboardParser()
    parsed.feed(document)
    assert not {"script", "link", "img", "iframe", "object", "embed", "form", "a"} & set(
        parsed.tags
    )
    assert not any(key.startswith("on") or key in {"src", "href"} for key, _ in parsed.attributes)
    assert "default-src 'none'" in document
    assert "@import" not in document
    assert "url(" not in document


def test_output_rejects_json_and_symlinks_without_modifying_reports(tmp_path: Path) -> None:
    report = write_report(tmp_path)
    original = report.read_bytes()
    linked = tmp_path / "linked.html"
    linked.symlink_to(report)

    for output in (report, linked):
        with pytest.raises(DashboardExportError):
            export_dashboard(tmp_path, output)

    assert report.read_bytes() == original
    assert linked.is_symlink()


def test_atomic_output_does_not_modify_report_hardlinks(tmp_path: Path) -> None:
    report = write_report(tmp_path)
    original = report.read_bytes()
    output = tmp_path / "dashboard.html"
    os.link(report, output)

    export_dashboard(tmp_path, output)
    export_dashboard(tmp_path, output)

    assert report.read_bytes() == original
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert not list(tmp_path.glob(".sentinellite-dashboard-*"))


def test_failed_output_replace_preserves_previous_dashboard_and_cleans_temporary_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "dashboard.html"
    output.write_text("previous dashboard", encoding="utf-8")

    def denied(*args):
        raise PermissionError("simulated replace denied")

    monkeypatch.setattr(Path, "replace", denied)

    with pytest.raises(DashboardExportError, match="Could not save dashboard"):
        export_dashboard(tmp_path, output)

    assert output.read_text(encoding="utf-8") == "previous dashboard"
    assert not list(tmp_path.glob(".sentinellite-dashboard-*"))


@pytest.mark.parametrize("limit", [0, -1, True])
def test_invalid_limits_fail_before_writing(tmp_path: Path, limit) -> None:
    output = tmp_path / "dashboard.html"

    with pytest.raises(DashboardExportError, match="positive integer"):
        export_dashboard(tmp_path, output, limit)

    assert not output.exists()


@pytest.mark.parametrize("has_report", [False, True])
def test_cli_exports_default_dashboard_without_any_observation_or_external_activity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    has_report: bool,
) -> None:
    monkeypatch.chdir(tmp_path)
    if has_report:
        write_report(tmp_path / "reports")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Dashboard export must only read stored reports and write HTML")

    for target in (
        "sentinellite.main.collect_system_info",
        "sentinellite.main.discover_auth_log_sources",
        "sentinellite.main.run_demo",
        "sentinellite.main.run_doctor",
        "sentinellite.main.run_auth_scan",
        "sentinellite.main.run_process_scan",
        "sentinellite.main.run_network_scan",
        "sentinellite.main.run_file_integrity_scan",
        "sentinellite.main.run_file_integrity_baseline_scan",
        "sentinellite.main.create_file_integrity_baseline",
        "sentinellite.collectors.auth.collect_auth_events_from_file",
        "sentinellite.collectors.process.collect_processes",
        "sentinellite.collectors.network.collect_network_connections",
        "sentinellite.collectors.file_integrity.collect_file_integrity",
        "sentinellite.detection.engine.detect_events",
        "sentinellite.scoring.risk.score_rule_matches",
        "sentinellite.explanations.generator.generate_alert_explanation",
        "sentinellite.reporting.notification.write_notification_summary",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.create_connection",
        "socket.socket.connect",
        "socket.socket.connect_ex",
        "socket.socket.sendto",
        "subprocess.Popen",
        "os.system",
        "webbrowser.open",
    ):
        monkeypatch.setattr(target, forbidden)

    result = runner.invoke(app, ["dashboard", "export"])

    assert result.exit_code == 0, result.output
    assert "Saved dashboard: reports/dashboard.html" in result.stdout
    assert (tmp_path / "reports" / "dashboard.html").is_file()


def test_cli_explicit_paths_and_limit(tmp_path: Path) -> None:
    reports_dir = tmp_path / "input reports"
    output = tmp_path / "new [output]" / "view.html"
    write_report(reports_dir, alerts=[{"title": "Displayed"}, {"title": "HIDDEN"}])

    result = runner.invoke(
        app,
        [
            "dashboard",
            "export",
            "--reports-dir",
            str(reports_dir),
            "--output",
            str(output),
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert str(output) in result.stdout
    assert "Displayed" in output.read_text(encoding="utf-8")
    assert "HIDDEN" not in output.read_text(encoding="utf-8")


def test_cli_invalid_limit_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["dashboard", "export", "--limit", "0"])

    assert result.exit_code == 2
    assert not (tmp_path / "reports").exists()


def test_cli_directory_error_is_actionable(tmp_path: Path) -> None:
    not_directory = tmp_path / "reports"
    not_directory.write_text("existing file", encoding="utf-8")
    output = tmp_path / "dashboard.html"

    result = runner.invoke(
        app,
        [
            "dashboard",
            "export",
            "--reports-dir",
            str(not_directory),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1
    assert "Dashboard export failed" in result.stdout
    assert "not a directory" in result.stdout
    assert "Traceback" not in result.output
    assert not output.exists()
