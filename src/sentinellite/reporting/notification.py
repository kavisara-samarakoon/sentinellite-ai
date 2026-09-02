from collections import Counter
from dataclasses import dataclass

from sentinellite.reporting.review import ReviewedReport

NOTIFICATION_SCHEMA_VERSION = 1
NOTIFICATION_OUTPUT_TYPE = "sentinellite_notification_summary"
MAX_INCLUDED_ALERTS = 20


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
