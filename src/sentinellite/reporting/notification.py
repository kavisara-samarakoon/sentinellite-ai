import json
import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sentinellite.reporting.review import ReviewedReport

NOTIFICATION_SCHEMA_VERSION = 1
NOTIFICATION_OUTPUT_TYPE = "sentinellite_notification_summary"
MAX_INCLUDED_ALERTS = 20


class NotificationOutputError(Exception):
    """Raised for expected local notification output failures."""


@dataclass(frozen=True, slots=True)
class NotificationAlertSummary:
    """Privacy-minimized fields from one stored reviewed alert."""

    rule_id: str
    category: str
    severity: str
    risk_score: int | float
    risk_level: str


@dataclass(frozen=True, slots=True)
class NotificationSummary:
    """Deterministic local notification summary for one reviewed report."""

    schema_version: int
    output_type: str
    source_report_id: str
    source_generated_at: str
    alert_count: int
    included_alert_count: int
    omitted_alert_count: int
    severity_counts: dict[str, int]
    risk_level_counts: dict[str, int]
    alerts: tuple[NotificationAlertSummary, ...]


def build_notification_summary(report: ReviewedReport) -> NotificationSummary:
    """Build a privacy-minimized summary from already-reviewed stored alerts."""
    severity_counts = Counter(alert.severity for alert in report.alerts)
    risk_level_counts = Counter(alert.risk_level for alert in report.alerts)
    ranked_alerts = sorted(
        report.alerts,
        key=lambda alert: alert.risk_score,
        reverse=True,
    )
    included_alerts = tuple(
        NotificationAlertSummary(
            rule_id=alert.rule_id,
            category=alert.category,
            severity=alert.severity,
            risk_score=alert.risk_score,
            risk_level=alert.risk_level,
        )
        for alert in ranked_alerts[:MAX_INCLUDED_ALERTS]
    )
    included_alert_count = len(included_alerts)

    return NotificationSummary(
        schema_version=NOTIFICATION_SCHEMA_VERSION,
        output_type=NOTIFICATION_OUTPUT_TYPE,
        source_report_id=report.report_id,
        source_generated_at=report.generated_at.isoformat(),
        alert_count=report.alert_count,
        included_alert_count=included_alert_count,
        omitted_alert_count=report.alert_count - included_alert_count,
        severity_counts=dict(sorted(severity_counts.items())),
        risk_level_counts=dict(sorted(risk_level_counts.items())),
        alerts=included_alerts,
    )


def notification_summary_to_dict(summary: NotificationSummary) -> dict[str, object]:
    """Serialize only the notification summary contract's approved fields."""
    return {
        "schema_version": summary.schema_version,
        "output_type": summary.output_type,
        "source": {
            "report_id": summary.source_report_id,
            "generated_at": summary.source_generated_at,
        },
        "alert_count": summary.alert_count,
        "included_alert_count": summary.included_alert_count,
        "omitted_alert_count": summary.omitted_alert_count,
        "severity_counts": dict(summary.severity_counts),
        "risk_level_counts": dict(summary.risk_level_counts),
        "alerts": [
            {
                "rule_id": alert.rule_id,
                "category": alert.category,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "risk_level": alert.risk_level,
            }
            for alert in summary.alerts
        ],
    }


def write_notification_summary(
    summary: NotificationSummary,
    output_path: Path,
) -> Path:
    """Create one private local JSON summary without overwriting another path."""
    _validate_output_location(output_path)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)

    try:
        file_descriptor = os.open(output_path, flags, 0o600)
    except FileExistsError as error:
        raise NotificationOutputError(
            "Notification output path already exists; overwrite refused."
        ) from error
    except IsADirectoryError as error:
        raise NotificationOutputError(
            "Notification output path is an existing directory."
        ) from error
    except OSError as error:
        raise NotificationOutputError(
            "Could not create the notification output file."
        ) from error

    created_stat: os.stat_result | None = None
    descriptor_owned = True
    try:
        created_stat = os.fstat(file_descriptor)
        output_file = os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        )
        descriptor_owned = False
        with output_file:
            json.dump(
                notification_summary_to_dict(summary),
                output_file,
                indent=2,
                sort_keys=True,
            )
            output_file.write("\n")
    except (OSError, TypeError, ValueError) as error:
        if descriptor_owned:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        _cleanup_partial_output(output_path, created_stat)
        raise NotificationOutputError(
            "Could not write the notification summary; partial output was removed."
        ) from error

    return output_path


def _validate_output_location(output_path: Path) -> None:
    try:
        parent_stat = output_path.parent.stat()
    except FileNotFoundError as error:
        raise NotificationOutputError(
            "Notification output parent directory does not exist."
        ) from error
    except OSError as error:
        raise NotificationOutputError(
            "Could not inspect the notification output parent directory."
        ) from error

    if not stat.S_ISDIR(parent_stat.st_mode):
        raise NotificationOutputError(
            "Notification output parent path is not a directory."
        )

    try:
        target_stat = output_path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise NotificationOutputError(
            "Could not inspect the notification output path."
        ) from error

    if stat.S_ISLNK(target_stat.st_mode):
        raise NotificationOutputError(
            "Notification output path is an existing symbolic link."
        )
    if stat.S_ISDIR(target_stat.st_mode):
        raise NotificationOutputError(
            "Notification output path is an existing directory."
        )
    if stat.S_ISREG(target_stat.st_mode):
        raise NotificationOutputError(
            "Notification output path already exists; overwrite refused."
        )
    raise NotificationOutputError(
        "Notification output path exists and is not a regular file."
    )


def _cleanup_partial_output(
    output_path: Path,
    created_stat: os.stat_result | None,
) -> None:
    if created_stat is None:
        return

    try:
        current_stat = output_path.lstat()
    except (FileNotFoundError, OSError):
        return

    created_identity = (created_stat.st_dev, created_stat.st_ino)
    current_identity = (current_stat.st_dev, current_stat.st_ino)
    if stat.S_ISREG(current_stat.st_mode) and current_identity == created_identity:
        try:
            output_path.unlink()
        except OSError:
            pass
