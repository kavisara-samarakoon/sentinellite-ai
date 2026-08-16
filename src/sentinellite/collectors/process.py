from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import psutil


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """Normalized information about a running process."""

    pid: int
    name: str
    username: str | None
    exe: str | None
    cmdline: list[str]
    cpu_percent: float
    memory_percent: float
    status: str | None

    def to_dict(self) -> dict[str, Any]:
        """Convert process information to a dictionary."""
        return asdict(self)


def collect_processes() -> list[ProcessInfo]:
    """
    Collect a normalized list of running processes.

    Some process fields may be unavailable without root privileges.
    In those cases, missing values are safely replaced with defaults.
    """
    process_attributes = [
        "pid",
        "name",
        "username",
        "exe",
        "cmdline",
        "cpu_percent",
        "memory_percent",
        "status",
    ]

    processes: list[ProcessInfo] = []

    for process in psutil.process_iter(attrs=process_attributes, ad_value=None):
        try:
            process_data = process.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

        process_info = ProcessInfo(
            pid=int(process_data.get("pid") or 0),
            name=str(process_data.get("name") or "unknown"),
            username=process_data.get("username"),
            exe=process_data.get("exe"),
            cmdline=list(process_data.get("cmdline") or []),
            cpu_percent=float(process_data.get("cpu_percent") or 0.0),
            memory_percent=float(process_data.get("memory_percent") or 0.0),
            status=process_data.get("status"),
        )

        processes.append(process_info)

    return processes


def processes_to_dicts(processes: list[ProcessInfo]) -> list[dict[str, Any]]:
    """Convert a list of ProcessInfo objects to dictionaries."""
    return [process.to_dict() for process in processes]
