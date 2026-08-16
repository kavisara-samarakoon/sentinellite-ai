from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinellite.collectors.system import SystemInfo, collect_system_info
from sentinellite.config.loader import ConfigError, load_config
from sentinellite.pipeline.auth_scan import run_auth_scan
from sentinellite.pipeline.process_scan import run_process_scan
from sentinellite.reporting.json_reporter import read_alert_report

console = Console()

app = typer.Typer(
    help="SentinelLite AI - Lightweight Linux endpoint detection and monitoring agent.",
    invoke_without_command=True,
)


def show_banner(config: dict[str, Any]) -> None:
    app_name = config["app"].get("name", "SentinelLite AI")
    version = config["app"].get("version", "0.1.0")

    banner = f"""
{app_name} v{version}
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
        monitoring["network"].get("description", ""),
    )
    table.add_row(
        "File Integrity Monitor",
        format_status(monitoring["file_integrity"]["enabled"]),
        monitoring["file_integrity"].get("description", ""),
    )
    table.add_row(
        "JSON Reporting",
        format_status(reporting["json_reports"]["enabled"]),
        f"Output directory: {reporting['json_reports'].get('output_dir', 'reports')}",
    )
    table.add_row(
        "AI-Assisted Explanation",
        format_status(ai_analysis.get("enabled", False)),
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
    else:
        console.print("[green][+] No process alerts generated.[/green]")


if __name__ == "__main__":
    app()
