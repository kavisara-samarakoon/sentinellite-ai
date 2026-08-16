import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinellite.scoring.risk import ScoredAlert


@dataclass(frozen=True)
class AlertReport:
    report_id: str
    report_type: str
    generated_at: str
    alert_count: int
    alerts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def create_alert_report(scored_alerts: list[ScoredAlert]) -> AlertReport:
    generated_at = datetime.now(UTC).isoformat()
    report_id = f"sentinellite-report-{generated_at}"

    return AlertReport(
        report_id=report_id,
        report_type="sentinellite_alert_report",
        generated_at=generated_at,
        alert_count=len(scored_alerts),
        alerts=[alert.to_dict() for alert in scored_alerts],
    )


def write_alert_report(
    scored_alerts: list[ScoredAlert],
    output_dir: str | Path = "reports",
    filename: str | None = None,
) -> Path:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = create_alert_report(scored_alerts)

    safe_timestamp = report.generated_at.replace(":", "-").replace("+", "_")
    report_filename = filename or f"alerts-{safe_timestamp}.json"
    report_path = output_path / report_filename

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report.to_dict(), file, indent=2)

    return report_path


def read_alert_report(report_path: str | Path) -> dict[str, Any]:
    path = Path(report_path)

    if not path.exists():
        raise FileNotFoundError(f"Alert report not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise TypeError("Alert report must contain a JSON object.")

    return data
