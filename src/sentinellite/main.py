import platform
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinellite import __version__
from sentinellite.collectors.auth_sources import (
    DEFAULT_AUTH_LOG_CANDIDATES,
    AuthLogSourceError,
    discover_auth_log_sources,
)
from sentinellite.collectors.system import SystemInfo, collect_system_info
from sentinellite.config import SentinelLiteConfig, default_config, write_default_config
from sentinellite.config.loader import ConfigError, load_config
from sentinellite.detection.rules import DetectionRule, active_rules_from_disabled_ids
from sentinellite.explanations.cli import build_explanation_panels
from sentinellite.explanations.evidence import build_alert_evidence_summary
from sentinellite.explanations.generator import generate_alert_explanation
from sentinellite.pipeline.auth_scan import run_auth_scan
from sentinellite.pipeline.file_integrity_baseline_scan import (
    create_file_integrity_baseline,
    run_file_integrity_baseline_scan,
)
from sentinellite.pipeline.file_integrity_scan import run_file_integrity_scan
from sentinellite.pipeline.network_scan import run_network_scan
from sentinellite.pipeline.process_scan import run_process_scan
from sentinellite.reporting.json_reporter import read_alert_report
from sentinellite.reporting.notification import (
    NotificationOutputError,
    build_notification_summary,
    write_notification_summary,
)
from sentinellite.reporting.review import (
    ReportReviewError,
    build_report_summary,
    list_report_entries,
    load_review_report,
)

console = Console()
CURRENT_VERSION = __version__

app = typer.Typer(
    help="SentinelLite AI - Local defensive observation and report-review CLI.",
    invoke_without_command=True,
)
reports_app = typer.Typer(
    help="Review local SentinelLite JSON alert reports.",
    no_args_is_help=True,
)
auth_sources_app = typer.Typer(
    help="Inspect common Linux authentication log source candidates.",
    no_args_is_help=True,
)
app.add_typer(reports_app, name="reports")
app.add_typer(auth_sources_app, name="auth-sources")


def _literal_text(
    value: object,
    *,
    max_length: int | None = None,
    style: str | None = None,
) -> Text:
    rendered = "".join(character if character.isprintable() else " " for character in str(value))
    if max_length is not None and len(rendered) > max_length:
        rendered = f"{rendered[: max_length - 3]}..."
    return Text(rendered, style=style)


def _format_summary_sequence(value: object) -> str:
    if not isinstance(value, (list, tuple)):
        return "-"
    return ", ".join(str(item) for item in value) or "-"


def _format_summary_counts(value: object) -> str:
    if not isinstance(value, Mapping):
        return "-"
    return ", ".join(f"{key}: {count}" for key, count in value.items()) or "-"


def _alert_value(alert: object, field_name: str) -> object | None:
    if isinstance(alert, Mapping):
        return alert.get(field_name)
    return getattr(alert, field_name, None)


def _show_alert_explanations(alerts: Iterable[object]) -> None:
    explanations = []

    for alert in alerts:
        rule_id = _alert_value(alert, "rule_id")
        if not isinstance(rule_id, str):
            continue
        explanations.append(
            generate_alert_explanation(
                rule_id,
                build_alert_evidence_summary(alert),
            )
        )

    if not explanations:
        return

    console.print()
    console.print("[bold cyan]Deterministic Alert Explanations[/bold cyan]")
    for panel in build_explanation_panels(explanations):
        console.print(panel)


def _selected_config(ctx: typer.Context) -> SentinelLiteConfig:
    config = ctx.obj
    if not isinstance(config, SentinelLiteConfig):
        return default_config()
    return config


def _reporting_options(
    ctx: typer.Context,
    output_dir: Path | None,
    include_explanations: bool | None,
) -> tuple[Path, bool]:
    config = _selected_config(ctx)

    effective_output_dir = (
        output_dir if output_dir is not None else config.reporting.output_dir
    )
    effective_include_explanations = (
        include_explanations
        if include_explanations is not None
        else config.reporting.include_explanations
    )
    return effective_output_dir, effective_include_explanations


def _active_rules(ctx: typer.Context) -> list[DetectionRule] | None:
    disabled_ids = _selected_config(ctx).rules.disabled_ids
    if not disabled_ids:
        return None
    return active_rules_from_disabled_ids(disabled_ids)


def _require_module_enabled(
    ctx: typer.Context,
    module_name: str,
    display_name: str,
) -> None:
    config = _selected_config(ctx)
    if not getattr(config.modules, module_name):
        console.print(
            f"[red][!] {display_name} monitoring is disabled by configuration.[/red]"
        )
        raise typer.Exit(code=1)


def show_banner(config: dict[str, Any]) -> None:
    app_name = config["app"].get("name", "SentinelLite AI")

    banner = f"""
{app_name} v{CURRENT_VERSION}
Local Defensive Observation CLI
"""
    console.print(Panel.fit(banner, title=app_name, border_style="cyan"))


def show_system_info(system_info: SystemInfo) -> None:
    table = Table(title="System Information")
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Hostname", system_info.hostname)
    table.add_row("Operating System", system_info.operating_system)
    table.add_row("OS Release", system_info.os_release)
    table.add_row("Architecture", system_info.architecture)
    table.add_row("Python Version", system_info.python_version)
    table.add_row("Runtime Mode", system_info.runtime_mode)

    console.print(table)


def format_status(enabled: bool) -> str:
    if enabled:
        return "[green]Enabled[/green]"

    return "[red]Disabled[/red]"


def format_not_implemented_status() -> str:
    return "[yellow]Not implemented[/yellow]"


def show_modules(
    display_config: dict[str, Any],
    selected_config: SentinelLiteConfig,
) -> None:
    monitoring = display_config["monitoring"]

    table = Table(title="Available Local Capabilities")
    table.add_column("Module", style="bold")
    table.add_column("Status")
    table.add_column("Description")

    table.add_row(
        "Authentication Scan",
        format_status(selected_config.modules.authentication),
        monitoring["authentication"].get("description", ""),
    )
    table.add_row(
        "Process Scan",
        format_status(selected_config.modules.process),
        monitoring["process"].get("description", ""),
    )
    table.add_row(
        "Network Observation",
        format_status(selected_config.modules.network),
        "Read-only observation of active network connection metadata",
    )
    table.add_row(
        "File Integrity Check",
        format_status(selected_config.modules.file_integrity),
        "On-demand observation of explicitly selected file paths",
    )
    table.add_row(
        "JSON Reporting",
        format_status(True),
        f"Output directory: {selected_config.reporting.output_dir}",
    )
    table.add_row(
        "Real AI / LLM Execution",
        format_not_implemented_status(),
        "Deterministic local explanation templates only",
    )

    console.print(table)


def show_risk_thresholds(config: dict[str, Any]) -> None:
    risk = config["risk"]

    table = Table(title="Risk Thresholds")
    table.add_column("Level", style="bold")
    table.add_column("Minimum Score")

    table.add_row("Low", str(risk["low"]))
    table.add_row("Medium", str(risk["medium"]))
    table.add_row("High", str(risk["high"]))
    table.add_row("Critical", str(risk["critical"]))

    console.print(table)


def show_status(selected_config: SentinelLiteConfig) -> None:
    try:
        display_config = load_config()
    except ConfigError as error:
        console.print(f"[red][!] Configuration error: {error}[/red]")
        raise typer.Exit(code=1) from error

    system_info = collect_system_info()

    show_banner(display_config)
    console.print("[cyan]SentinelLite AI status[/cyan]\n")

    show_system_info(system_info)
    console.print()
    show_modules(display_config, selected_config)
    console.print()
    show_risk_thresholds(display_config)

    console.print("\n[green][+] Status: AVAILABLE[/green]")

    if system_info.operating_system != "Linux":
        console.print(
            "[yellow][!] Note: SentinelLite AI is designed for Linux endpoint observation. "
            "You are currently running it in development mode.[/yellow]"
        )


@app.callback()
def main(
    ctx: typer.Context,
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="Load settings from this SentinelLite TOML configuration file.",
        ),
    ] = None,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the SentinelLite AI version and exit.",
            is_eager=True,
        ),
    ] = False,
) -> None:
    if version:
        typer.echo(f"SentinelLite AI v{__version__}")
        raise typer.Exit()

    try:
        ctx.obj = default_config() if config_path is None else load_config(config_path)
    except ConfigError as error:
        console.print(f"[red][!] Failed to load configuration: {error}[/red]")
        raise typer.Exit(code=1) from error

    if ctx.invoked_subcommand is None:
        show_status(_selected_config(ctx))


@app.command("config-init")
def config_init_command(
    path: Annotated[
        Path,
        typer.Option(
            "--path",
            help="Path for the new SentinelLite TOML configuration file.",
        ),
    ] = Path("sentinellite.toml"),
) -> None:
    """Create a default SentinelLite TOML configuration file."""
    try:
        created_path = write_default_config(path)
    except (ConfigError, OSError) as error:
        console.print(f"[red][!] Configuration error: {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print(f"[green][+] Created default config:[/green] {created_path}")
    console.print(
        "Example: sentinellite "
        f"--config {created_path} scan-auth examples/auth_logs/sample_auth.log"
    )


@auth_sources_app.command("list")
def auth_sources_list_command() -> None:
    """List common Linux authentication log candidates without scanning them."""
    entries = discover_auth_log_sources(DEFAULT_AUTH_LOG_CANDIDATES)

    table = Table(title="Linux Authentication Log Candidates")
    table.add_column("Family")
    table.add_column("Path")
    table.add_column("Status")
    table.add_column("Diagnostic")

    for entry in entries:
        status_style = {
            "available": "green",
            "missing": "yellow",
            "unreadable": "red",
            "unsupported": "red",
        }.get(entry.status)
        table.add_row(
            _literal_text(entry.family, max_length=40),
            _literal_text(entry.path, max_length=120),
            _literal_text(entry.status, max_length=24, style=status_style),
            _literal_text(entry.error or "-", max_length=160),
        )

    console.print(table)

    if platform.system() != "Linux":
        console.print(
            _literal_text(
                "Note: These are Linux authentication log candidates. "
                "Explicit sample or custom paths remain supported by scan-auth.",
                style="yellow",
            )
        )


@reports_app.command("list")
def reports_list_command(
    ctx: typer.Context,
    report_dir: Annotated[
        Path | None,
        typer.Option(
            "--report-dir",
            help="Directory containing SentinelLite JSON alert reports.",
        ),
    ] = None,
) -> None:
    """List local SentinelLite JSON alert reports without modifying them."""
    effective_report_dir = (
        report_dir
        if report_dir is not None
        else _selected_config(ctx).reporting.output_dir
    )

    try:
        entries = list_report_entries(effective_report_dir)
    except ReportReviewError as error:
        console.print(
            _literal_text(
                f"[!] Report review error: {error}",
                max_length=240,
                style="red",
            )
        )
        raise typer.Exit(code=1) from error

    if not entries:
        console.print(
            _literal_text(
                f"No JSON alert reports found in {effective_report_dir}",
                max_length=240,
            )
        )
        return

    table = Table(title="SentinelLite Alert Reports")
    table.add_column("Generated At")
    table.add_column("Alerts", justify="right")
    table.add_column("Report Type")
    table.add_column("Status")
    table.add_column("File")

    invalid_entries = []
    for entry in entries:
        if entry.status == "invalid":
            invalid_entries.append(entry)

        generated_at = entry.generated_at.isoformat() if entry.generated_at else "-"
        alert_count = str(entry.alert_count) if entry.alert_count is not None else "-"
        report_type = entry.report_type if entry.report_type is not None else "-"
        status_style = "green" if entry.status == "valid" else "red"

        table.add_row(
            _literal_text(generated_at, max_length=40),
            _literal_text(alert_count, max_length=12),
            _literal_text(report_type, max_length=40),
            _literal_text(entry.status, max_length=16, style=status_style),
            _literal_text(entry.path.name, max_length=80),
        )

    console.print(table)

    for entry in invalid_entries:
        diagnostic = entry.error or "Report is invalid."
        console.print(
            _literal_text(
                f"Invalid report {entry.path.name}: {diagnostic}",
                max_length=240,
                style="red",
            )
        )

    if invalid_entries:
        raise typer.Exit(code=1)


@reports_app.command("show")
def reports_show_command(report_path: Path) -> None:
    """Show a safe summary of one local SentinelLite JSON alert report."""
    try:
        report = load_review_report(report_path)
        summary = build_report_summary(report)
    except ReportReviewError as error:
        console.print(
            _literal_text(
                f"[!] Report review error: {error}",
                max_length=240,
                style="red",
            )
        )
        raise typer.Exit(code=1) from error

    summary_table = Table(title="SentinelLite Alert Report Summary")
    summary_table.add_column("Field", style="bold")
    summary_table.add_column("Value")
    summary_table.add_row("File path", _literal_text(summary["path"], max_length=160))
    summary_table.add_row("Report ID", _literal_text(summary["report_id"], max_length=120))
    summary_table.add_row(
        "Report type",
        _literal_text(summary["report_type"], max_length=60),
    )
    summary_table.add_row(
        "Generated timestamp",
        _literal_text(summary["generated_at"], max_length=60),
    )
    summary_table.add_row("Alert count", _literal_text(summary["alert_count"]))
    summary_table.add_row(
        "Stored explanation count",
        _literal_text(summary["explanation_count"]),
    )
    summary_table.add_row(
        "Rule IDs",
        _literal_text(_format_summary_sequence(summary["rule_ids"]), max_length=160),
    )
    summary_table.add_row(
        "Severity counts",
        _literal_text(_format_summary_counts(summary["severity_counts"]), max_length=160),
    )
    summary_table.add_row(
        "Risk level counts",
        _literal_text(_format_summary_counts(summary["risk_level_counts"]), max_length=160),
    )
    console.print(summary_table)

    alert_table = Table(title="Stored Alerts")
    alert_table.add_column("Rule ID")
    alert_table.add_column("Severity")
    alert_table.add_column("Risk")
    alert_table.add_column("Category")
    alert_table.add_column("Message")
    alert_table.add_column("Explanation")

    for alert in report.alerts:
        alert_table.add_row(
            _literal_text(alert.rule_id, max_length=32),
            _literal_text(alert.severity, max_length=20),
            _literal_text(f"{alert.risk_level} ({alert.risk_score})", max_length=32),
            _literal_text(alert.category, max_length=40),
            _literal_text(alert.message, max_length=120),
            _literal_text("yes" if alert.has_explanation else "no"),
        )

    console.print(alert_table)
    if not report.alerts:
        console.print(_literal_text("No alerts stored in this report."))


@reports_app.command("export-notification")
def reports_export_notification_command(
    report_path: Path,
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Exact path for the local notification summary JSON file.",
        ),
    ],
) -> None:
    """Export a privacy-minimized local notification summary from one report."""
    try:
        report = load_review_report(report_path)
        try:
            resolved_report_path = report.path.resolve()
            resolved_output_path = output.resolve(strict=False)
        except (OSError, RuntimeError):
            pass
        else:
            if resolved_output_path == resolved_report_path:
                raise NotificationOutputError(
                    "Notification output path must differ from the source report path."
                )

        summary = build_notification_summary(report)
        written_path = write_notification_summary(summary, output)
    except ReportReviewError as error:
        console.print(
            _literal_text(
                f"[!] Report review error: {error}",
                max_length=240,
                style="red",
            )
        )
        raise typer.Exit(code=1) from error
    except NotificationOutputError as error:
        console.print(
            _literal_text(
                f"[!] Notification export error: {error}",
                max_length=240,
                style="red",
            )
        )
        raise typer.Exit(code=1) from error

    console.print(
        _literal_text(
            "[+] Notification summary exported successfully.",
            style="green",
        )
    )
    result_table = Table(title="Local Notification Summary Export")
    result_table.add_column("Field", style="bold")
    result_table.add_column("Value")
    result_table.add_row(
        "Source report ID",
        _literal_text(summary.source_report_id, max_length=120),
    )
    result_table.add_row("Total alerts", _literal_text(summary.alert_count))
    result_table.add_row(
        "Included alerts",
        _literal_text(summary.included_alert_count),
    )
    result_table.add_row(
        "Omitted alerts",
        _literal_text(summary.omitted_alert_count),
    )
    console.print(result_table)
    console.print(
        _literal_text(f"Output path: {written_path}"),
        soft_wrap=True,
    )


@app.command("scan-auth")
def scan_auth_command(
    ctx: typer.Context,
    log_path: Path,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory for the JSON alert report."),
    ] = None,
    include_explanations: Annotated[
        bool | None,
        typer.Option(
            "--include-explanations/--no-include-explanations",
            help="Include deterministic alert explanations in the JSON report.",
        ),
    ] = None,
) -> None:
    """Scan an authentication log file and generate a JSON alert report."""
    _require_module_enabled(ctx, "authentication", "Authentication")
    effective_output_dir, effective_include_explanations = _reporting_options(
        ctx,
        output_dir,
        include_explanations,
    )
    rules = _active_rules(ctx)
    try:
        summary, scored_alerts = run_auth_scan(
            log_path=log_path,
            output_dir=effective_output_dir,
            include_explanations=effective_include_explanations,
            rules=rules,
        )
    except (AuthLogSourceError, FileNotFoundError) as error:
        console.print(
            _literal_text(
                f"[!] Authentication log source error: {error}",
                max_length=240,
                style="red",
            )
        )
        raise typer.Exit(code=1) from error

    console.print(Panel.fit("Authentication Scan Complete", title="SentinelLite AI", border_style="green"))

    table = Table(title="Auth Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Log file", summary.log_path)
    table.add_row("Auth events found", str(summary.auth_events_count))
    table.add_row("Security events created", str(summary.security_events_count))
    table.add_row("Detection matches", str(summary.detection_matches_count))
    table.add_row("Scored alerts", str(summary.scored_alerts_count))
    table.add_row("JSON report", summary.report_path)

    console.print(table)

    if scored_alerts:
        alert_table = Table(title="Generated Alerts")
        alert_table.add_column("Rule ID", style="bold")
        alert_table.add_column("Risk")
        alert_table.add_column("Message")

        for alert in scored_alerts:
            alert_table.add_row(
                alert.rule_id,
                f"{alert.risk_level.upper()} ({alert.risk_score})",
                alert.message,
            )

        console.print(alert_table)
        _show_alert_explanations(scored_alerts)
    else:
        console.print("[yellow][!] No alerts generated.[/yellow]")


@app.command("scan-process")
def scan_process_command(
    ctx: typer.Context,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory for the JSON alert report."),
    ] = None,
    include_explanations: Annotated[
        bool | None,
        typer.Option(
            "--include-explanations/--no-include-explanations",
            help="Include deterministic alert explanations in the JSON report.",
        ),
    ] = None,
) -> None:
    """Scan running processes and generate a JSON alert report."""
    _require_module_enabled(ctx, "process", "Process")
    effective_output_dir, effective_include_explanations = _reporting_options(
        ctx,
        output_dir,
        include_explanations,
    )
    rules = _active_rules(ctx)
    summary = run_process_scan(
        output_dir=effective_output_dir,
        include_explanations=effective_include_explanations,
        rules=rules,
    )

    console.print(Panel.fit("Process Scan Complete", title="SentinelLite AI", border_style="green"))

    table = Table(title="Process Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Processes found", str(summary.processes_count))
    table.add_row("Security events created", str(summary.security_events_count))
    table.add_row("Detection matches", str(summary.detection_matches_count))
    table.add_row("Scored alerts", str(summary.scored_alerts_count))
    table.add_row("JSON report", summary.report_path)

    console.print(table)

    if summary.scored_alerts_count:
        report = read_alert_report(summary.report_path)
        alerts = report.get("alerts", [])

        alert_table = Table(title="Generated Alerts")
        alert_table.add_column("Rule ID", style="bold")
        alert_table.add_column("Risk")
        alert_table.add_column("Message")

        for alert in alerts:
            risk_level = str(alert.get("risk_level", "unknown")).upper()
            risk_score = alert.get("risk_score", "?")
            alert_table.add_row(
                str(alert.get("rule_id", "unknown")),
                f"{risk_level} ({risk_score})",
                str(alert.get("message", "")),
            )

        console.print(alert_table)
        _show_alert_explanations(alerts)
    else:
        console.print("[green][+] No process alerts generated.[/green]")


@app.command("scan-network")
def scan_network_command(
    ctx: typer.Context,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory for the JSON alert report."),
    ] = None,
    include_explanations: Annotated[
        bool | None,
        typer.Option(
            "--include-explanations/--no-include-explanations",
            help="Include deterministic alert explanations in the JSON report.",
        ),
    ] = None,
) -> None:
    """Collect network connection observations and generate a JSON alert report."""
    _require_module_enabled(ctx, "network", "Network")
    effective_output_dir, effective_include_explanations = _reporting_options(
        ctx,
        output_dir,
        include_explanations,
    )
    rules = _active_rules(ctx)
    summary = run_network_scan(
        output_dir=effective_output_dir,
        include_explanations=effective_include_explanations,
        rules=rules,
    )

    console.print(Panel.fit("Network Scan Complete", title="SentinelLite AI", border_style="green"))

    table = Table(title="Network Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Connections found", str(summary.connections_count))
    table.add_row("Security events created", str(summary.security_events_count))
    table.add_row("Detection matches", str(summary.detection_matches_count))
    table.add_row("Scored alerts", str(summary.scored_alerts_count))
    table.add_row("JSON report", summary.report_path)

    console.print(table)

    if summary.scored_alerts_count:
        report = read_alert_report(summary.report_path)
        alerts = report.get("alerts", [])

        alert_table = Table(title="Generated Alerts")
        alert_table.add_column("Rule ID", style="bold")
        alert_table.add_column("Risk")
        alert_table.add_column("Message")

        for alert in alerts:
            risk_level = str(alert.get("risk_level", "unknown")).upper()
            risk_score = alert.get("risk_score", "?")
            alert_table.add_row(
                str(alert.get("rule_id", "unknown")),
                f"{risk_level} ({risk_score})",
                str(alert.get("message", "")),
            )

        console.print(alert_table)
        _show_alert_explanations(alerts)
    else:
        console.print("[green][+] No network alerts generated.[/green]")


@app.command("scan-files")
def scan_files_command(
    ctx: typer.Context,
    paths: Annotated[
        list[Path],
        typer.Argument(help="One or more explicit file paths to observe without modification."),
    ],
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory for the JSON alert report."),
    ] = None,
    include_explanations: Annotated[
        bool | None,
        typer.Option(
            "--include-explanations/--no-include-explanations",
            help="Include deterministic alert explanations in the JSON report.",
        ),
    ] = None,
) -> None:
    """Observe selected file paths and generate a JSON alert report."""
    _require_module_enabled(ctx, "file_integrity", "File integrity")
    effective_output_dir, effective_include_explanations = _reporting_options(
        ctx,
        output_dir,
        include_explanations,
    )
    rules = _active_rules(ctx)
    summary = run_file_integrity_scan(
        paths=paths,
        output_dir=effective_output_dir,
        include_explanations=effective_include_explanations,
        rules=rules,
    )

    console.print(
        Panel.fit(
            "File Integrity Scan Complete",
            title="SentinelLite AI",
            border_style="green",
        )
    )

    table = Table(title="File Integrity Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Files checked", str(summary.files_checked_count))
    table.add_row("Security events created", str(summary.security_events_count))
    table.add_row("Detection matches", str(summary.detection_matches_count))
    table.add_row("Scored alerts", str(summary.scored_alerts_count))
    table.add_row("JSON report", summary.report_path)

    console.print(table)

    if summary.scored_alerts_count:
        report = read_alert_report(summary.report_path)
        alerts = report.get("alerts", [])

        alert_table = Table(title="Generated Alerts")
        alert_table.add_column("Rule ID", style="bold")
        alert_table.add_column("Risk")
        alert_table.add_column("Message")

        for alert in alerts:
            risk_level = str(alert.get("risk_level", "unknown")).upper()
            risk_score = alert.get("risk_score", "?")
            alert_table.add_row(
                str(alert.get("rule_id", "unknown")),
                f"{risk_level} ({risk_score})",
                str(alert.get("message", "")),
            )

        console.print(alert_table)
        _show_alert_explanations(alerts)
    else:
        console.print("[green][+] No file integrity alerts generated.[/green]")


@app.command("baseline-files")
def baseline_files_command(
    ctx: typer.Context,
    paths: Annotated[
        list[Path],
        typer.Argument(help="One or more explicit file paths to record in the baseline."),
    ],
    baseline_path: Annotated[
        Path,
        typer.Option(
            "--baseline-path",
            help="Explicit JSON file path for the file integrity baseline.",
        ),
    ],
) -> None:
    """Create a file integrity baseline for explicitly selected paths."""
    _require_module_enabled(ctx, "file_integrity", "File integrity")
    try:
        summary = create_file_integrity_baseline(
            paths=[str(path) for path in paths],
            baseline_path=baseline_path,
        )
    except FileNotFoundError as error:
        console.print(f"[red][!] {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print(
        Panel.fit(
            "File Integrity Baseline Created",
            title="SentinelLite AI",
            border_style="green",
        )
    )

    table = Table(title="File Integrity Baseline Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Files checked", str(summary.files_checked_count))
    table.add_row("Baseline entries", str(summary.baseline_entries_count))
    table.add_row("Baseline JSON path", str(summary.baseline_path))

    console.print(table)
    console.print(
        f"[green][+] Baseline JSON path:[/green] {summary.baseline_path}",
        soft_wrap=True,
    )


@app.command("scan-files-baseline")
def scan_files_baseline_command(
    ctx: typer.Context,
    baseline_path: Annotated[
        Path,
        typer.Option(
            "--baseline-path",
            help="Path to an existing file integrity baseline JSON file.",
        ),
    ],
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir",
            help="Directory for the generated JSON alert report.",
        ),
    ] = None,
    include_explanations: Annotated[
        bool | None,
        typer.Option(
            "--include-explanations/--no-include-explanations",
            help="Include deterministic alert explanations in the JSON report.",
        ),
    ] = None,
) -> None:
    """Scan the exact paths stored in a file integrity baseline."""
    _require_module_enabled(ctx, "file_integrity", "File integrity")
    effective_output_dir, effective_include_explanations = _reporting_options(
        ctx,
        output_dir,
        include_explanations,
    )
    rules = _active_rules(ctx)
    try:
        summary = run_file_integrity_baseline_scan(
            baseline_path=baseline_path,
            output_dir=effective_output_dir,
            include_explanations=effective_include_explanations,
            rules=rules,
        )
    except FileNotFoundError as error:
        console.print(f"[red][!] {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print(
        Panel.fit(
            "File Integrity Baseline Scan Complete",
            title="SentinelLite AI",
            border_style="green",
        )
    )

    table = Table(title="File Integrity Baseline Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Baseline path", str(summary.baseline_path))
    table.add_row("Files checked", str(summary.files_checked_count))
    table.add_row("Comparisons", str(summary.comparisons_count))
    table.add_row("Security events", str(summary.security_events_count))
    table.add_row("Detection matches", str(summary.detection_matches_count))
    table.add_row("Scored alerts", str(summary.scored_alerts_count))
    table.add_row("JSON report path", str(summary.report_path))

    console.print(table)
    console.print(
        f"[green][+] JSON report path:[/green] {summary.report_path}",
        soft_wrap=True,
    )

    if summary.scored_alerts_count:
        report = read_alert_report(summary.report_path)
        alerts = report.get("alerts", [])

        alert_table = Table(title="Generated Alerts")
        alert_table.add_column("Rule ID", style="bold")
        alert_table.add_column("Risk")
        alert_table.add_column("Message")

        for alert in alerts:
            risk_level = str(alert.get("risk_level", "unknown")).upper()
            risk_score = alert.get("risk_score", "?")
            alert_table.add_row(
                str(alert.get("rule_id", "unknown")),
                f"{risk_level} ({risk_score})",
                str(alert.get("message", "")),
            )

        console.print(alert_table)
        _show_alert_explanations(alerts)
    else:
        console.print("[green][+] No baseline file integrity alerts generated.[/green]")


def cli() -> None:
    """Run the SentinelLite AI command-line application."""
    app()


if __name__ == "__main__":
    cli()
