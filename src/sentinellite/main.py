import platform
import socket
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def get_runtime_mode() -> str:
    os_name = platform.system()

    if os_name == "Linux":
        return "Linux target environment"
    if os_name == "Darwin":
        return "macOS development environment"
    return "Unsupported or untested environment"


def show_banner() -> None:
    banner = """
SentinelLite AI v0.1
Linux Endpoint Security Monitoring Agent
"""
    console.print(Panel.fit(banner, title="SentinelLite AI", border_style="cyan"))


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


def show_modules() -> None:
    table = Table(title="Monitoring Modules")
    table.add_column("Module", style="bold")
    table.add_column("Status")

    table.add_row("Authentication Monitor", "Planned")
    table.add_row("Process Monitor", "Planned")
    table.add_row("Network Monitor", "Planned")
    table.add_row("File Integrity Monitor", "Planned")
    table.add_row("Risk Scoring", "Planned")
    table.add_row("JSON Reporting", "Planned")
    table.add_row("AI-Assisted Explanation", "Planned")

    console.print(table)


def main() -> None:
    show_banner()
    console.print("[green][+] Starting SentinelLite AI...[/green]\n")

    show_system_info()
    console.print()
    show_modules()

    console.print("\n[green][+] Status: READY[/green]")

    if platform.system() != "Linux":
        console.print(
            "[yellow][!] Note: SentinelLite AI is designed for Linux monitoring. "
            "You are currently running it in development mode.[/yellow]"
        )


if __name__ == "__main__":
    main()
