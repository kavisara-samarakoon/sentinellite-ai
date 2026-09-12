"""Export a standalone, offline HTML view of stored local reports."""

import html
import json
import math
import os
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from heapq import nlargest
from pathlib import Path
from tempfile import NamedTemporaryFile

from sentinellite.reporting.review import (
    MAX_REPORT_SIZE_BYTES,
    SUPPORTED_REPORT_TYPE,
    ReportReviewError,
    discover_report_paths,
)

SAFETY_BANNER = (
    "Local static report viewer. No live monitoring, no network activity, no automatic remediation."
)
SEVERITIES = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_OLDEST = datetime.min.replace(tzinfo=UTC)


class DashboardExportError(Exception):
    """An input directory or output file cannot be used for a dashboard export."""


@dataclass(frozen=True)
class DashboardAlert:
    timestamp: datetime | None
    severity: str
    rule_id: str
    title: str
    source: str
    module: str
    risk_score: str
    summary: str


@dataclass(frozen=True)
class DashboardReport:
    filename: str
    generated_at: datetime | None
    alert_count: int
    alerts: tuple[DashboardAlert, ...]


@dataclass(frozen=True)
class DashboardData:
    reports_loaded: int
    reports_skipped: int
    reports: tuple[DashboardReport, ...]
    alerts: tuple[DashboardAlert, ...]
    limit: int


def _text(*values: object, length: int = 160) -> str:
    """Select a short string field; never stringify arbitrary objects or evidence."""
    for value in values:
        if isinstance(value, str) and value.strip():
            clean = " ".join(value.split())
            clean = "".join(character for character in clean if character.isprintable())
            return clean if len(clean) <= length else clean[: length - 3] + "..."
    return "—"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        # Existing reports include an offset. An ambiguous or invalid time is unavailable.
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _time_label(value: datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value is not None else "Unavailable"


def _alert(data: dict, generated_at: datetime | None) -> DashboardAlert:
    explanation = data.get("explanation")
    explanation = explanation if isinstance(explanation, dict) else {}
    score = data.get("risk_score")
    score_text = (
        str(score) if type(score) is int or (type(score) is float and math.isfinite(score)) else "—"
    )
    return DashboardAlert(
        timestamp=_timestamp(data.get("timestamp")) or generated_at,
        severity=_text(data.get("severity"), "unknown", length=40).lower(),
        rule_id=_text(data.get("rule_id"), length=80),
        title=_text(data.get("rule_name"), data.get("title"), data.get("name"), "Untitled alert"),
        source=_text(
            data.get("source"), data.get("module"), data.get("category"), data.get("event_type")
        ),
        module=_text(
            data.get("module"), data.get("category"), data.get("source"), data.get("event_type")
        ),
        risk_score=_text(score_text, length=32),
        summary=_text(
            explanation.get("summary"),
            data.get("summary"),
            data.get("message"),
            data.get("description"),
            length=240,
        ),
    )


def _load_report(path: Path, limit: int) -> DashboardReport:
    """Read one bounded regular file; never follow a report symlink or block on a FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise ValueError("Report symlinks are not supported.")
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as report_file:
        file_stat = os.fstat(report_file.fileno())
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_REPORT_SIZE_BYTES:
            raise ValueError("Report must be a regular file within the report size limit.")
        encoded = report_file.read(MAX_REPORT_SIZE_BYTES + 1)
    if len(encoded) > MAX_REPORT_SIZE_BYTES:
        raise ValueError("Report exceeds the report size limit.")
    data = json.loads(encoded.decode("utf-8"))
    if not isinstance(data, dict) or data.get("report_type") != SUPPORTED_REPORT_TYPE:
        raise ValueError("Unsupported report type.")
    alerts = data.get("alerts")
    if not isinstance(alerts, list) or any(not isinstance(item, dict) for item in alerts):
        raise ValueError("Report alerts must be an array of objects.")
    count = data.get("alert_count", len(alerts))
    if type(count) is not int or count != len(alerts):
        raise ValueError("Report alert count does not match its alerts.")
    generated_at = _timestamp(data.get("generated_at"))
    selected = nlargest(
        limit,
        (_alert(item, generated_at) for item in alerts),
        key=lambda alert: alert.timestamp or _OLDEST,
    )
    return DashboardReport(_text(path.name), generated_at, count, tuple(selected))


def load_dashboard_data(reports_dir: Path, limit: int = 25) -> DashboardData:
    """Count valid reports and retain only the newest limited report/alert projections."""
    if type(limit) is not int or limit < 1:
        raise DashboardExportError("Limit must be a positive integer.")
    try:
        paths = discover_report_paths(reports_dir)
    except ReportReviewError as error:
        if isinstance(error.__cause__, FileNotFoundError):
            paths = []
        else:
            raise DashboardExportError(str(error)) from error

    loaded = 0
    skipped = 0

    def reports():
        nonlocal loaded, skipped
        for path in paths:
            try:
                report = _load_report(path, limit)
            except (OSError, ValueError, RecursionError):
                skipped += 1
                continue
            loaded += 1
            yield report

    selected = nlargest(limit, reports(), key=lambda report: report.generated_at or _OLDEST)
    alerts = nlargest(
        limit,
        (alert for report in selected for alert in report.alerts),
        key=lambda alert: alert.timestamp or _OLDEST,
    )
    return DashboardData(loaded, skipped, tuple(selected), tuple(alerts), limit)


_CSS = """
:root { color-scheme: light; font-family: system-ui, sans-serif; color: #172b3a;
  background: #f3f6f8; line-height: 1.5; }
* { box-sizing: border-box; }
body { margin: 0; }
main { max-width: 1440px; padding: 40px 28px; margin: auto; }
h1 { font-size: clamp(1.7rem, 4vw, 2.5rem); line-height: 1.2; margin: 8px 0 16px; }
h2 { font-size: 1.15rem; margin: 0 0 16px; }
h3 { font-size: .85rem; margin: 0 0 12px; color: #526675; }
.eyebrow { font-size: .75rem; font-weight: 750; letter-spacing: .13em; color: #12645f; }
.banner { border-left: 4px solid #168279; background: #e3f3ef; padding: 16px 20px;
  border-radius: 6px; }
.muted, footer { color: #526675; font-size: .875rem; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px;
  margin: 24px 0; }
.card, section { background: #fff; border: 1px solid #dbe4ea; border-radius: 12px;
  padding: 22px; }
.card strong { display: block; font-size: 1.7rem; margin-top: 8px; overflow-wrap: anywhere; }
.card .time { font-size: .95rem; }
section { margin: 20px 0; }
.breakdowns { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 32px; }
dl { margin: 0; } dl div { display: flex; justify-content: space-between; gap: 16px;
  border-top: 1px solid #edf1f4; padding: 9px 0; }
dt { overflow-wrap: anywhere; } dd { margin: 0; font-weight: 700; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: left; font-size: .85rem; }
caption { text-align: left; padding-bottom: 14px; color: #526675; }
th { font-size: .75rem; color: #526675; background: #f6f8fa; }
th, td { padding: 12px; border-bottom: 1px solid #e4eaee; vertical-align: top;
  overflow-wrap: anywhere; max-width: 280px; }
.badge { display: inline-block; border-radius: 6px; padding: 3px 8px; font-weight: 700;
  background: #edf1f4; color: #374e60; }
.critical, .high { color: #962d39; background: #fce9ec; }
.medium { color: #81500d; background: #fff2d8; }
.low, .info { color: #11615a; background: #e3f3ef; }
footer { margin-top: 28px; }
@media (max-width: 760px) { main { padding: 24px 14px; }
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .breakdowns { grid-template-columns: 1fr; gap: 20px; } section { padding: 16px; } }
@media print { :root { background: #fff; } main { padding: 0; }
  .table-wrap { overflow: visible; } }
"""


def _breakdown(title: str, counts: Counter) -> str:
    items = "".join(
        f"<div><dt>{_escape(label)}</dt><dd>{_escape(count)}</dd></div>"
        for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    )
    return f"<div><h3>{_escape(title)}</h3><dl>{items}</dl></div>"


def _alert_row(alert: DashboardAlert) -> str:
    severity_class = alert.severity if alert.severity in SEVERITIES else "unknown"
    cells = (
        _escape(_time_label(alert.timestamp)),
        f'<span class="badge {_escape(severity_class)}">{_escape(alert.severity)}</span>',
        _escape(alert.rule_id),
        _escape(alert.title),
        _escape(alert.source),
        _escape(alert.risk_score),
        _escape(alert.summary),
    )
    return "<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>"


def render_dashboard(data: DashboardData) -> str:
    """Render only selected summary fields, escaping every dynamic HTML value."""
    severities = Counter(alert.severity for alert in data.alerts)
    highest = max(severities, key=lambda value: SEVERITIES.get(value, -1), default="None")
    latest = data.reports[0].generated_at if data.reports else None
    cards = "".join(
        f'<div class="card"><span class="muted">{_escape(label)}</span>'
        f'<strong class="{style}">{_escape(value)}</strong></div>'
        for label, value, style in (
            ("Total reports loaded", data.reports_loaded, ""),
            ("Total alerts shown", len(data.alerts), ""),
            ("Highest severity shown", highest, ""),
            ("Latest report time (UTC)", _time_label(latest), "time"),
        )
    )
    breakdowns = (
        _breakdown("Severity counts", severities)
        + _breakdown("Rule counts", Counter(alert.rule_id for alert in data.alerts))
        + _breakdown("Module counts", Counter(alert.module for alert in data.alerts))
    )
    report_rows = "".join(
        f"<tr><td>{_escape(report.filename)}</td>"
        f"<td>{_escape(_time_label(report.generated_at))}</td>"
        f"<td>{_escape(report.alert_count)}</td></tr>"
        for report in data.reports
    )
    alert_rows = "".join(_alert_row(alert) for alert in data.alerts)
    if not report_rows:
        report_rows = (
            '<tr><td colspan="3">No reports were found. No valid reports are available.</td></tr>'
        )
    if not alert_rows:
        alert_rows = '<tr><td colspan="7">No alerts to display.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>SentinelLite AI Local Dashboard</title><style>{_CSS}</style></head>
<body><main><header><div class="eyebrow">BETA · SAVED LOCAL REPORTS</div>
<h1>SentinelLite AI Local Dashboard</h1><p class="banner">{_escape(SAFETY_BANNER)}</p>
<p class="muted">A snapshot of stored reports. Alerts are review aids, not proof of compromise.</p>
</header><div class="cards">{cards}</div>
<p class="muted">Showing {_escape(len(data.reports))} of {_escape(data.reports_loaded)} loaded reports
and up to {_escape(data.limit)} alerts from those reports. Skipped files: {_escape(data.reports_skipped)}.
Counts and highest severity describe the alerts shown. Times use UTC; unavailable times sort last.</p>
<section><h2>Alert breakdown</h2><div class="breakdowns">{breakdowns}</div></section>
<section><h2>Latest alerts</h2><div class="table-wrap"><table>
<caption>Newest available alert time first; report time is used when alert time is unavailable.</caption>
<thead><tr><th scope="col">Timestamp (UTC)</th><th scope="col">Severity</th>
<th scope="col">Rule ID</th><th scope="col">Title / name</th><th scope="col">Source / module / type</th>
<th scope="col">Risk score</th><th scope="col">Short explanation / summary</th></tr></thead>
<tbody>{alert_rows}</tbody></table></div></section>
<section><h2>Reports shown</h2><div class="table-wrap"><table>
<thead><tr><th scope="col">Report file</th><th scope="col">Report time (UTC)</th>
<th scope="col">Stored alerts</th></tr></thead><tbody>{report_rows}</tbody></table></div></section>
<footer>Generated from local SentinelLite AI JSON reports.</footer></main></body></html>
"""


def export_dashboard(
    reports_dir: Path = Path("reports"),
    output: Path = Path("reports/dashboard.html"),
    limit: int = 25,
) -> Path:
    """Write an HTML snapshot atomically, without overwriting any source report."""
    if output.suffix.lower() not in {".html", ".htm"}:
        raise DashboardExportError("Dashboard output must have an .html or .htm extension.")
    if output.is_symlink():
        raise DashboardExportError("Dashboard output must not be a symbolic link.")
    if output.exists() and not output.is_file():
        raise DashboardExportError("Dashboard output must be a regular HTML file.")
    data = load_dashboard_data(reports_dir, limit)
    document = render_dashboard(data)
    temporary_path = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=".sentinellite-dashboard-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(document)
        temporary_path.replace(output)
    except OSError as error:
        raise DashboardExportError(f"Could not save dashboard '{output}': {error}") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return output
