from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinellite.collectors.system import SystemInfo, collect_system_info
from sentinellite.config.loader import ConfigError, load_config
from sentinellite.explanations.cli import build_explanation_panels
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

console = Console()
CURRENT_VERSION = "0.3.0-alpha"

app = typer.Typer(
    help="SentinelLite AI - Lightweight Linux endpoint detection and monitoring agent.",
    invoke_without_command=True,
)


def _alert_value(alert: object, field_name: str) -> object | None:
    if isinstance(alert, Mapping):
        return alert.get(field_name)
    return getattr(alert, field_name, None)


def _build_alert_evidence_summary(alert: object) -> dict[str, object]:
    evidence_summary: dict[str, object] = {}

    for output_name, field_name in (
        ("rule_id", "rule_id"),
        ("severity", "severity"),
        ("score", "risk_score"),
        ("event_type", "event_type"),
        ("source", "source"),
        ("message", "message"),
    ):
        value = _alert_value(alert, field_name)
        if value is not None:
            evidence_summary[output_name] = value

    alert_evidence = _alert_value(alert, "evidence")
    if isinstance(alert_evidence, Mapping):
        for field_name in ("path", "status"):
            value = alert_evidence.get(field_name)
            if value is not None:
                evidence_summary[field_name] = value

    return evidence_summary


def _show_alert_explanations(alerts: Iterable[object]) -> None:
    explanations = []

    for alert in alerts:
        rule_id = _alert_value(alert, "rule_id")
        if not isinstance(rule_id, str):
            continue
        explanations.append(
            generate_alert_explanation(
                rule_id,
                _build_alert_evidence_summary(alert),
            )
        )

    if not explanations:
        return

    console.print()
    console.print("[bold cyan]Deterministic Alert Explanations[/bold cyan]")
    for panel in build_explanation_panels(explanations):
        console.print(panel)


def show_banner(config: dict[str, Any]) -> None:
    app_name = config["app"].get("name", "SentinelLite AI")

    banner = f"""
{app_name} v{CURRENT_VERSION}
Linux Endpoint Security Monitoring Agent
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


def format_planned_status() -> str:
    return "[yellow]Planned[/yellow]"


def show_modules(config: dict[str, Any]) -> None:
    monitoring = config["monitoring"]
    reporting = config["reporting"]
    ai_analysis = config.get("ai_analysis", {})

    table = Table(title="Monitoring Modules")
    table.add_column("Module", style="bold")
    table.add_column("Status")
    table.add_column("Description")

    table.add_row(
        "Authentication Monitor",
        format_status(monitoring["authentication"]["enabled"]),
        monitoring["authentication"].get("description", ""),
    )
    table.add_row(
        "Process Monitor",
        format_status(monitoring["process"]["enabled"]),
        monitoring["process"].get("description", ""),
    )
    table.add_row(
        "Network Monitor",
        format_status(monitoring["network"]["enabled"]),
        "Monitor active network connections and investigation-focused network activity",
    )
    table.add_row(
        "File Integrity Monitor",
        format_status(monitoring["file_integrity"]["enabled"]),
        "Observe selected file paths for integrity-related investigation signals",
    )
    table.add_row(
        "JSON Reporting",
        format_status(reporting["json_reports"]["enabled"]),
        f"Output directory: {reporting['json_reports'].get('output_dir', 'reports')}",
    )
    table.add_row(
        "AI-Assisted Explanation",
        format_planned_status(),
        ai_analysis.get("note", "Optional explanation layer"),
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


def show_status() -> None:
    try:
        config = load_config()
    except ConfigError as error:
        console.print(f"[red][!] Configuration error: {error}[/red]")
        raise typer.Exit(code=1) from error

    system_info = collect_system_info()

    show_banner(config)
    console.print("[green][+] Starting SentinelLite AI...[/green]\n")

    show_system_info(system_info)
    console.print()
    show_modules(config)
    console.print()
    show_risk_thresholds(config)

    console.print("\n[green][+] Status: READY[/green]")

    if system_info.operating_system != "Linux":
        console.print(
            "[yellow][!] Note: SentinelLite AI is designed for Linux monitoring. "
            "You are currently running it in development mode.[/yellow]"
        )


@app.callback()
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_status()


@app.command("scan-auth")
def scan_auth_command(
    log_path: Path,
    output_dir: Path = Path("reports"),
) -> None:
    """Scan an authentication log file and generate a JSON alert report."""
    try:
        summary, scored_alerts = run_auth_scan(
            log_path=log_path,
            output_dir=output_dir,
        )
    except FileNotFoundError as error:
        console.print(f"[red][!] {error}[/red]")
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
    output_dir: Path = Path("reports"),
) -> None:
    """Scan running processes and generate a JSON alert report."""
    summary = run_process_scan(output_dir=output_dir)

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
    output_dir: Path = Path("reports"),
) -> None:
    """Collect network connection observations and generate a JSON alert report."""
    summary = run_network_scan(output_dir=output_dir)

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
    paths: Annotated[
        list[Path],
        typer.Argument(help="One or more explicit file paths to observe without modification."),
    ],
    output_dir: Path = Path("reports"),
) -> None:
    """Observe selected file paths and generate a JSON alert report."""
    summary = run_file_integrity_scan(paths=paths, output_dir=output_dir)

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
    baseline_path: Annotated[
        Path,
        typer.Option(
            "--baseline-path",
            help="Path to an existing file integrity baseline JSON file.",
        ),
    ],
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Directory for the generated JSON alert report.",
        ),
    ] = Path("reports"),
) -> None:
    """Scan the exact paths stored in a file integrity baseline."""
    try:
        summary = run_file_integrity_baseline_scan(
            baseline_path=baseline_path,
            output_dir=output_dir,
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


if __name__ == "__main__":
    app()
