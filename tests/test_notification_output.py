import ast
import inspect
import json
import os
import stat
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path

import pytest

import sentinellite.reporting.notification as notification_module
from sentinellite.reporting.notification import (
    MAX_INCLUDED_ALERTS,
    NOTIFICATION_OUTPUT_TYPE,
    NOTIFICATION_SCHEMA_VERSION,
    NotificationAlertSummary,
    NotificationOutputError,
    NotificationSummary,
    build_notification_summary,
    notification_summary_to_dict,
    write_notification_summary,
)
from sentinellite.reporting.review import (
    IncompatibleReportError,
    ReviewedAlert,
    ReviewedReport,
    load_review_report,
    validate_report_data,
)

EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "output_type",
    "source",
    "alert_count",
    "included_alert_count",
    "omitted_alert_count",
    "severity_counts",
    "risk_level_counts",
    "alerts",
}
EXPECTED_ALERT_KEYS = {
    "rule_id",
    "category",
    "severity",
    "risk_score",
    "risk_level",
}


def reviewed_alert(
    rule_id: str = "AUTH-001",
    *,
    category: str = "authentication",
    severity: str = "medium",
    risk_score: int = 50,
    risk_level: str = "medium",
    message: str = "Failed SSH login for root from 192.0.2.10",
    has_explanation: bool = False,
) -> ReviewedAlert:
    return ReviewedAlert(
        rule_id=rule_id,
        severity=severity,
        risk_level=risk_level,
        risk_score=risk_score,
        category=category,
        message=message,
        has_explanation=has_explanation,
    )


def reviewed_report(
    alerts: tuple[ReviewedAlert, ...] = (),
    *,
    path: Path = Path("private/reports/alerts-sensitive.json"),
    report_id: str = "sentinellite-report-2026-09-02T10:00:00+00:00",
    generated_at: datetime = datetime(2026, 9, 2, 10, 0, tzinfo=UTC),
) -> ReviewedReport:
    return ReviewedReport(
        path=path,
        report_id=report_id,
        report_type="sentinellite_alert_report",
        generated_at=generated_at,
        alert_count=len(alerts),
        alerts=alerts,
    )


def test_notification_constants_and_dataclasses_are_frozen_and_slotted() -> None:
    assert NOTIFICATION_SCHEMA_VERSION == 1
    assert NOTIFICATION_OUTPUT_TYPE == "sentinellite_notification_summary"
    assert MAX_INCLUDED_ALERTS == 20
    assert NotificationAlertSummary.__slots__
    assert NotificationSummary.__slots__

    summary = build_notification_summary(reviewed_report())
    with pytest.raises(FrozenInstanceError):
        summary.alert_count = 1  # type: ignore[misc]


def test_notification_serializer_uses_exact_schema_keys() -> None:
    data = notification_summary_to_dict(
        build_notification_summary(reviewed_report((reviewed_alert(),)))
    )

    assert set(data) == EXPECTED_TOP_LEVEL_KEYS
    assert data["schema_version"] == NOTIFICATION_SCHEMA_VERSION
    assert data["output_type"] == NOTIFICATION_OUTPUT_TYPE
    assert data["source"] == {
        "report_id": "sentinellite-report-2026-09-02T10:00:00+00:00",
        "generated_at": "2026-09-02T10:00:00+00:00",
    }
    alerts = data["alerts"]
    assert isinstance(alerts, list)
    assert set(alerts[0]) == EXPECTED_ALERT_KEYS


def test_zero_alert_report_produces_empty_summary() -> None:
    summary = build_notification_summary(reviewed_report())

    assert summary.alert_count == 0
    assert summary.included_alert_count == 0
    assert summary.omitted_alert_count == 0
    assert summary.severity_counts == {}
    assert summary.risk_level_counts == {}
    assert summary.alerts == ()


def test_builder_counts_severity_and_risk_levels_deterministically() -> None:
    report = reviewed_report(
        (
            reviewed_alert(severity="low", risk_level="info", risk_score=10),
            reviewed_alert("AUTH-002", severity="medium", risk_level="low", risk_score=30),
            reviewed_alert("AUTH-003", severity="medium", risk_level="medium", risk_score=50),
        )
    )

    summary = build_notification_summary(report)

    assert summary.severity_counts == {"low": 1, "medium": 2}
    assert summary.risk_level_counts == {"info": 1, "low": 1, "medium": 1}


def test_builder_orders_by_descending_stored_risk_score_with_stable_ties() -> None:
    report = reviewed_report(
        (
            reviewed_alert("LOW", risk_score=10),
            reviewed_alert("FIRST-TIE", risk_score=80),
            reviewed_alert("SECOND-TIE", risk_score=80),
            reviewed_alert("MIDDLE", risk_score=40),
        )
    )

    summary = build_notification_summary(report)

    assert [alert.rule_id for alert in summary.alerts] == [
        "FIRST-TIE",
        "SECOND-TIE",
        "MIDDLE",
        "LOW",
    ]
    assert [alert.risk_score for alert in summary.alerts] == [80, 80, 40, 10]


def test_builder_truncates_to_maximum_and_records_omitted_count() -> None:
    alerts = tuple(
        reviewed_alert(f"RULE-{index:03d}", risk_score=index)
        for index in range(MAX_INCLUDED_ALERTS + 7)
    )

    summary = build_notification_summary(reviewed_report(alerts))

    assert summary.alert_count == MAX_INCLUDED_ALERTS + 7
    assert summary.included_alert_count == MAX_INCLUDED_ALERTS
    assert summary.omitted_alert_count == 7
    assert len(summary.alerts) == MAX_INCLUDED_ALERTS
    assert summary.alerts[0].risk_score == MAX_INCLUDED_ALERTS + 6
    assert summary.alerts[-1].risk_score == 7


def test_builder_and_serializer_do_not_mutate_reviewed_report() -> None:
    report = reviewed_report(
        (
            reviewed_alert("LOW", risk_score=10),
            reviewed_alert("HIGH", risk_score=90, has_explanation=True),
        )
    )
    before = deepcopy(report)

    summary = build_notification_summary(report)
    notification_summary_to_dict(summary)

    assert report == before


def test_serialized_output_excludes_report_location_and_private_alert_content() -> None:
    sensitive_values = {
        "private/reports/alerts-sensitive.json",
        "alerts-sensitive.json",
        "root",
        "192.0.2.10",
        "/home/root/private.txt",
        "sudo cat /etc/shadow",
        "suspicious-process",
        "d2d2d2d2-private-hash",
        "stored explanation body",
        "stored explanation recommendation",
    }
    report = validate_report_data(
        {
            "report_id": "sentinellite-report-2026-09-02T10:00:00+00:00",
            "report_type": "sentinellite_alert_report",
            "generated_at": "2026-09-02T10:00:00+00:00",
            "alert_count": 1,
            "alerts": [
                {
                    "rule_id": "AUTH-001",
                    "category": "authentication",
                    "severity": "medium",
                    "risk_score": 50,
                    "risk_level": "medium",
                    "message": (
                        "User root at 192.0.2.10 accessed /home/root/private.txt; "
                        "command=sudo cat /etc/shadow; process=suspicious-process"
                    ),
                    "evidence": {
                        "username": "root",
                        "source_ip": "192.0.2.10",
                        "path": "/home/root/private.txt",
                        "command": "sudo cat /etc/shadow",
                        "process_name": "suspicious-process",
                        "sha256": "d2d2d2d2-private-hash",
                    },
                    "explanation": {
                        "summary": "stored explanation body",
                        "recommended_actions": [
                            "stored explanation recommendation"
                        ],
                        "evidence_summary": {"username": "root"},
                    },
                }
            ],
        },
        Path("private/reports/alerts-sensitive.json"),
    )

    data = notification_summary_to_dict(build_notification_summary(report))
    rendered = repr(data)

    for sensitive_value in sensitive_values:
        assert sensitive_value not in rendered
    assert "message" not in rendered
    assert "evidence" not in rendered
    assert "explanation" not in rendered
    assert "description" not in rendered
    assert "recommendation" not in rendered
    assert "event_id" not in rendered
    assert "alert_id" not in rendered


def test_stored_explanation_presence_does_not_change_notification_output() -> None:
    without_explanation = reviewed_report((reviewed_alert(has_explanation=False),))
    with_explanation = reviewed_report((reviewed_alert(has_explanation=True),))

    assert notification_summary_to_dict(
        build_notification_summary(without_explanation)
    ) == notification_summary_to_dict(build_notification_summary(with_explanation))


def test_builder_uses_stored_risk_score_without_rescoring() -> None:
    report = reviewed_report(
        (
            reviewed_alert(
                "STORED-LOW-SEVERITY-HIGH-SCORE",
                severity="info",
                risk_score=99,
                risk_level="custom-stored-level",
            ),
            reviewed_alert(
                "STORED-HIGH-SEVERITY-LOW-SCORE",
                severity="critical",
                risk_score=1,
                risk_level="another-stored-level",
            ),
        )
    )

    summary = build_notification_summary(report)

    assert [alert.rule_id for alert in summary.alerts] == [
        "STORED-LOW-SEVERITY-HIGH-SCORE",
        "STORED-HIGH-SEVERITY-LOW-SCORE",
    ]
    assert [alert.risk_score for alert in summary.alerts] == [99, 1]
    assert [alert.risk_level for alert in summary.alerts] == [
        "custom-stored-level",
        "another-stored-level",
    ]


def test_writer_produces_exact_pretty_json_schema_with_trailing_newline(
    tmp_path: Path,
) -> None:
    summary = build_notification_summary(reviewed_report((reviewed_alert(),)))
    output_path = tmp_path / "notification.json"
    expected_data = notification_summary_to_dict(summary)

    written_path = write_notification_summary(summary, output_path)

    assert written_path == output_path
    assert json.loads(output_path.read_text(encoding="utf-8")) == expected_data
    assert output_path.read_text(encoding="utf-8") == (
        json.dumps(expected_data, indent=2, sort_keys=True) + "\n"
    )


def test_writer_requires_existing_parent_directory(tmp_path: Path) -> None:
    output_path = tmp_path / "missing" / "notification.json"

    with pytest.raises(NotificationOutputError, match="parent directory does not exist"):
        write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert not output_path.parent.exists()
    assert not output_path.exists()


def test_writer_requires_parent_to_be_directory(tmp_path: Path) -> None:
    parent_file = tmp_path / "parent-file"
    parent_file.write_text("preserve parent", encoding="utf-8")
    output_path = parent_file / "notification.json"

    with pytest.raises(NotificationOutputError, match="parent path is not a directory"):
        write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert parent_file.read_text(encoding="utf-8") == "preserve parent"


def test_writer_refuses_existing_file_without_modification(tmp_path: Path) -> None:
    output_path = tmp_path / "existing.json"
    output_path.write_text("preserve existing output", encoding="utf-8")

    with pytest.raises(NotificationOutputError, match="overwrite refused"):
        write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert output_path.read_text(encoding="utf-8") == "preserve existing output"


def test_writer_refuses_existing_symlink_output(tmp_path: Path) -> None:
    symlink_target = tmp_path / "target.json"
    symlink_target.write_text("preserve target", encoding="utf-8")
    output_path = tmp_path / "notification.json"
    try:
        output_path.symlink_to(symlink_target)
    except OSError as error:
        pytest.skip(f"Symlink creation is unavailable: {error}")

    with pytest.raises(NotificationOutputError, match="symbolic link"):
        write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert output_path.is_symlink()
    assert symlink_target.read_text(encoding="utf-8") == "preserve target"


def test_writer_refuses_existing_directory_output(tmp_path: Path) -> None:
    output_path = tmp_path / "notification.json"
    output_path.mkdir()

    with pytest.raises(NotificationOutputError, match="existing directory"):
        write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert output_path.is_dir()


def test_writer_exclusive_creation_prevents_race_overwrite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "notification.json"
    real_open = os.open

    def racing_open(path: Path, flags: int, mode: int) -> int:
        output_path.write_text("created during race", encoding="utf-8")
        return real_open(path, flags, mode)

    monkeypatch.setattr("sentinellite.reporting.notification.os.open", racing_open)

    with pytest.raises(NotificationOutputError, match="overwrite refused"):
        write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert output_path.read_text(encoding="utf-8") == "created during race"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions are not available")
def test_writer_creates_owner_only_output_permissions(tmp_path: Path) -> None:
    output_path = tmp_path / "notification.json"

    write_notification_summary(build_notification_summary(reviewed_report()), output_path)

    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_write_failure_removes_only_new_partial_output_and_preserves_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    summary = build_notification_summary(reviewed_report((reviewed_alert(),)))
    summary_before = deepcopy(summary)
    output_path = tmp_path / "notification.json"
    unrelated_path = tmp_path / "unrelated.json"
    unrelated_path.write_text("preserve unrelated file", encoding="utf-8")

    def failing_dump(_data: object, output_file: object, **_kwargs: object) -> None:
        output_file.write("partial")  # type: ignore[attr-defined]
        raise OSError("simulated private write failure")

    monkeypatch.setattr("sentinellite.reporting.notification.json.dump", failing_dump)

    with pytest.raises(NotificationOutputError, match="partial output was removed"):
        write_notification_summary(summary, output_path)

    assert not output_path.exists()
    assert unrelated_path.read_text(encoding="utf-8") == "preserve unrelated file"
    assert summary == summary_before


def test_written_json_excludes_sensitive_report_and_alert_fields(tmp_path: Path) -> None:
    source_report = validate_report_data(
        {
            "report_id": "sentinellite-report-safe-id",
            "report_type": "sentinellite_alert_report",
            "generated_at": "2026-09-02T10:00:00+00:00",
            "alert_count": 1,
            "alerts": [
                {
                    "rule_id": "AUTH-001",
                    "category": "authentication",
                    "severity": "medium",
                    "risk_score": 50,
                    "risk_level": "medium",
                    "message": (
                        "PRIVATE_USER 192.0.2.10 /private/message/path "
                        "sudo PRIVATE_COMMAND --token PRIVATE_TOKEN"
                    ),
                    "description": "PRIVATE_DESCRIPTION",
                    "raw_data": "PRIVATE_RAW_SOURCE_JSON",
                    "evidence": {
                        "username": "PRIVATE_USER",
                        "source_ip": "192.0.2.10",
                        "path": "/private/path",
                        "process_name": "PRIVATE_PROCESS",
                        "cmdline": ["PRIVATE_COMMAND_LINE"],
                        "sha256": "PRIVATE_HASH",
                    },
                    "explanation": {
                        "summary": "PRIVATE_EXPLANATION",
                        "recommended_actions": ["PRIVATE_RECOMMENDATION"],
                        "evidence_summary": {"path": "/private/explanation/path"},
                    },
                }
            ],
        },
        Path("private-source-report.json"),
    )
    output_path = tmp_path / "notification.json"

    write_notification_summary(build_notification_summary(source_report), output_path)
    written_text = output_path.read_text(encoding="utf-8")

    for private_value in (
        "private-source-report.json",
        "PRIVATE_USER",
        "192.0.2.10",
        "/private/message/path",
        "PRIVATE_COMMAND",
        "PRIVATE_TOKEN",
        "PRIVATE_DESCRIPTION",
        "PRIVATE_RAW_SOURCE_JSON",
        "/private/path",
        "PRIVATE_PROCESS",
        "PRIVATE_COMMAND_LINE",
        "PRIVATE_HASH",
        "PRIVATE_EXPLANATION",
        "PRIVATE_RECOMMENDATION",
        "/private/explanation/path",
        '"message"',
        '"evidence"',
        '"explanation"',
    ):
        assert private_value not in written_text


def test_writer_does_not_modify_source_report_data(tmp_path: Path) -> None:
    source_path = tmp_path / "source-report.json"
    source_path.write_bytes(b'{"source": "preserve byte-for-byte"}\n')
    source_before = source_path.read_bytes()
    report = reviewed_report((reviewed_alert(),), path=source_path)

    write_notification_summary(
        build_notification_summary(report),
        tmp_path / "notification.json",
    )

    assert source_path.read_bytes() == source_before


def test_notification_json_is_not_a_compatible_sentinellite_alert_report(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "notification.json"
    write_notification_summary(
        build_notification_summary(reviewed_report((reviewed_alert(),))),
        output_path,
    )

    with pytest.raises(IncompatibleReportError, match="supported report_type"):
        load_review_report(output_path)


def test_notification_module_import_boundary_excludes_active_or_external_modules() -> None:
    syntax_tree = ast.parse(inspect.getsource(notification_module))
    imported_modules = {
        alias.name
        for node in ast.walk(syntax_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module
        for node in ast.walk(syntax_tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    forbidden_prefixes = (
        "subprocess",
        "socket",
        "urllib",
        "http",
        "requests",
        "sentinellite.collectors",
        "sentinellite.detection",
        "sentinellite.scoring",
        "sentinellite.explanations",
    )

    assert not any(
        imported_module == prefix or imported_module.startswith(f"{prefix}.")
        for imported_module in imported_modules
        for prefix in forbidden_prefixes
    )
