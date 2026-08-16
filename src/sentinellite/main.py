import platform
import socket
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinellite.config.loader import ConfigError, load_config

console = Console()


def get_runtime_mode() -> str:
    os_name = platform.system()

    if os_name == "Linux":
        return "Linux target environment"
    if os_name == "Darwin":
        return "macOS development environment"
    return "Unsupported or untested environment"


def show_banner(config: dict[str, Any]) -> None:
    app_name = config["app"].get("name", "SentinelLite AI")
    version = config["app"].get("version", "0.1.0")

    banner = f"""
{app_name} v{version}
Linux Endpoint Security Monitoring Agent
"""
    console.print(Panel.fit(banner, title=app_name, border_style="cyan"))


def show_system_info() -> None:
    table = Table(title="System Information")
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Hostname", socket.gethostname())
    table.add_row("Operating System", platform.system())
    table.add_row("OS Release", platform.release())
    table.add_row("Architecture", platform.machine())
    table.add_row("Python Version", sys.version.split()[0])
    table.add_row("Runtime Mode", get_runtime_mode())

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

    console.print(table)


def main() -> None:
    try:
        config = load_config()
    except ConfigError as error:
        console.print(f"[red][!] Configuration error: {error}[/red]")
        raise SystemExit(1) from error

    show_banner(config)
    console.print("[green][+] Starting SentinelLite AI...[/green]\n")

    show_system_info()
    console.print()
    show_modules(config)
    console.print()
    show_risk_thresholds(config)

    console.print("\n[green][+] Status: READY[/green]")

    if platform.system() != "Linux":
        console.print(
            "[yellow][!] Note: SentinelLite AI is designed for Linux monitoring. "
            "You are currently running it in development mode.[/yellow]"
        )


if __name__ == "__main__":
    main()
