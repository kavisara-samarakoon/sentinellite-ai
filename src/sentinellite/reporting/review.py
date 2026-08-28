import json
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

SUPPORTED_REPORT_TYPE = "sentinellite_alert_report"
MAX_REPORT_SIZE_BYTES = 2 * 1024 * 1024


class ReportReviewError(Exception):
    """Base error for expected report discovery, loading, and validation failures."""


class MalformedReportError(ReportReviewError):
    """Raised when a report cannot be decoded or parsed as JSON."""


class IncompatibleReportError(ReportReviewError):
    """Raised when parsed JSON does not match the supported alert report shape."""


@dataclass(frozen=True, slots=True)
class ReviewedAlert:
    rule_id: str
    severity: str
    risk_level: str
    risk_score: int
    category: str
    message: str
    has_explanation: bool


@dataclass(frozen=True, slots=True)
class ReviewedReport:
    path: Path
    report_id: str
    report_type: str
    generated_at: datetime
    alert_count: int
    alerts: tuple[ReviewedAlert, ...]


@dataclass(frozen=True, slots=True)
class ReportListEntry:
    path: Path
    generated_at: datetime | None
    alert_count: int | None
    report_type: str | None
    status: str
    error: str | None


def discover_report_paths(report_dir: Path) -> list[Path]:
    """Return regular lowercase JSON files directly inside a report directory."""
    try:
        directory_stat = report_dir.stat()
    except FileNotFoundError as error:
        raise ReportReviewError(f"Report directory not found: {report_dir}") from error
    except OSError as error:
        raise ReportReviewError(
            f"Unable to inspect report directory '{report_dir}': {error}"
        ) from error

    if not stat.S_ISDIR(directory_stat.st_mode):
        raise ReportReviewError(f"Report path is not a directory: {report_dir}")

    report_paths: list[Path] = []
    try:
        for candidate in report_dir.iterdir():
            if candidate.suffix != ".json" or candidate.is_symlink():
                continue
            if candidate.is_file():
                report_paths.append(candidate)
    except OSError as error:
        raise ReportReviewError(
            f"Unable to read report directory '{report_dir}': {error}"
        ) from error

    return sorted(report_paths, key=lambda path: (path.name, str(path)))


def load_review_report(path: Path) -> ReviewedReport:
    """Load one local JSON report and validate its supported review shape."""
    try:
        file_stat = path.stat()
    except FileNotFoundError as error:
        raise ReportReviewError(f"Report file not found: {path}") from error
    except OSError as error:
        raise ReportReviewError(f"Unable to inspect report file '{path}': {error}") from error

    if not stat.S_ISREG(file_stat.st_mode):
        raise ReportReviewError(f"Report path is not a regular file: {path}")
    if file_stat.st_size > MAX_REPORT_SIZE_BYTES:
        raise ReportReviewError(
            f"Report file exceeds the {MAX_REPORT_SIZE_BYTES}-byte size limit: {path}"
        )

    try:
        with path.open("rb") as report_file:
            encoded_data = report_file.read(MAX_REPORT_SIZE_BYTES + 1)
    except OSError as error:
        raise ReportReviewError(f"Unable to read report file '{path}': {error}") from error

    if len(encoded_data) > MAX_REPORT_SIZE_BYTES:
        raise ReportReviewError(
            f"Report file exceeds the {MAX_REPORT_SIZE_BYTES}-byte size limit: {path}"
        )

    try:
        text = encoded_data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MalformedReportError(f"Report file is not valid UTF-8: {path}") from error

    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise MalformedReportError(
            f"Malformed JSON in report '{path}' at line {error.lineno}, column {error.colno}."
        ) from error

    return validate_report_data(data, path)


def validate_report_data(data: object, path: Path) -> ReviewedReport:
    """Validate parsed report data without mutating the supplied object."""
    if not isinstance(data, dict):
        raise IncompatibleReportError(
            f"Report '{path}' must contain a JSON object at the top level."
        )

    report_type = data.get("report_type")
    if report_type != SUPPORTED_REPORT_TYPE:
        raise IncompatibleReportError(
            f"Report '{path}' must use supported report_type '{SUPPORTED_REPORT_TYPE}'."
        )

    report_id = data.get("report_id")
    if not isinstance(report_id, str) or not report_id.strip():
        raise IncompatibleReportError(
            f"Report '{path}' field 'report_id' must be a non-empty string."
        )

    generated_at_value = data.get("generated_at")
    if not isinstance(generated_at_value, str):
        raise IncompatibleReportError(
            f"Report '{path}' field 'generated_at' must be a timezone-aware ISO datetime string."
        )
    try:
        generated_at = datetime.fromisoformat(generated_at_value)
    except ValueError as error:
        raise IncompatibleReportError(
            f"Report '{path}' field 'generated_at' must be a parseable ISO datetime."
        ) from error
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise IncompatibleReportError(
            f"Report '{path}' field 'generated_at' must include a timezone offset."
        )

    alert_count = data.get("alert_count")
    if type(alert_count) is not int or alert_count < 0:
        raise IncompatibleReportError(
            f"Report '{path}' field 'alert_count' must be a non-negative integer."
        )

    alerts_data = data.get("alerts")
    if not isinstance(alerts_data, list):
        raise IncompatibleReportError(
            f"Report '{path}' field 'alerts' must be a JSON array."
        )
    if len(alerts_data) != alert_count:
        raise IncompatibleReportError(
            f"Report '{path}' field 'alert_count' does not match the number of alerts."
        )

    reviewed_alerts: list[ReviewedAlert] = []
    for index, alert_data in enumerate(alerts_data):
        if not isinstance(alert_data, dict):
            raise IncompatibleReportError(
                f"Report '{path}' alert at index {index} must be a JSON object."
            )

        rule_id = _require_alert_string(alert_data, "rule_id", index, path)
        severity = _require_alert_string(alert_data, "severity", index, path)
        risk_level = _require_alert_string(alert_data, "risk_level", index, path)
        category = _require_alert_string(alert_data, "category", index, path)
        message = _require_alert_string(alert_data, "message", index, path)

        risk_score = alert_data.get("risk_score")
        if type(risk_score) is not int:
            raise IncompatibleReportError(
                f"Report '{path}' alert at index {index} field 'risk_score' "
                "must be an integer."
            )

        reviewed_alerts.append(
            ReviewedAlert(
                rule_id=rule_id,
                severity=severity,
                risk_level=risk_level,
                risk_score=risk_score,
                category=category,
                message=message,
                has_explanation=isinstance(alert_data.get("explanation"), dict),
            )
        )

    return ReviewedReport(
        path=path,
        report_id=report_id,
        report_type=report_type,
        generated_at=generated_at,
        alert_count=alert_count,
        alerts=tuple(reviewed_alerts),
    )


def list_report_entries(report_dir: Path) -> list[ReportListEntry]:
    """Return valid and invalid report entries without hiding other candidates."""
    valid_entries: list[ReportListEntry] = []
    invalid_entries: list[ReportListEntry] = []

    for path in discover_report_paths(report_dir):
        try:
            report = load_review_report(path)
        except ReportReviewError as error:
            invalid_entries.append(
                ReportListEntry(
                    path=path,
                    generated_at=None,
                    alert_count=None,
                    report_type=None,
                    status="invalid",
                    error=str(error),
                )
            )
            continue

        valid_entries.append(
            ReportListEntry(
                path=report.path,
                generated_at=report.generated_at,
                alert_count=report.alert_count,
                report_type=report.report_type,
                status="valid",
                error=None,
            )
        )

    valid_entries.sort(key=lambda entry: (entry.path.name, str(entry.path)))
    valid_entries.sort(key=lambda entry: entry.generated_at, reverse=True)
    invalid_entries.sort(key=lambda entry: (entry.path.name, str(entry.path)))
    return [*valid_entries, *invalid_entries]


def build_report_summary(report: ReviewedReport) -> dict[str, object]:
    """Build a deterministic summary without evidence or regenerated explanations."""
    severity_counts = Counter(alert.severity for alert in report.alerts)
    risk_level_counts = Counter(alert.risk_level for alert in report.alerts)

    return {
        "path": str(report.path),
        "report_id": report.report_id,
        "report_type": report.report_type,
        "generated_at": report.generated_at.isoformat(),
        "alert_count": report.alert_count,
        "explanation_count": sum(alert.has_explanation for alert in report.alerts),
        "rule_ids": sorted({alert.rule_id for alert in report.alerts}),
        "severity_counts": dict(sorted(severity_counts.items())),
        "risk_level_counts": dict(sorted(risk_level_counts.items())),
    }


def _require_alert_string(
    alert_data: dict[object, object],
    field_name: str,
    index: int,
    path: Path,
) -> str:
    value = alert_data.get(field_name)
    if not isinstance(value, str):
        raise IncompatibleReportError(
            f"Report '{path}' alert at index {index} field '{field_name}' must be a string."
        )
    return value
