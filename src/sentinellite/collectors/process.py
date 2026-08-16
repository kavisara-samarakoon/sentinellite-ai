from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import psutil

TEMPORARY_EXECUTION_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


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


def is_process_running_from_temp_path(process: ProcessInfo) -> bool:
    """
    Check whether a process executable appears to run from a temporary path.

    Temporary paths are commonly writable by normal users. This does not always
    mean malicious activity, but it is suspicious enough to investigate.
    """
    executable_path = process.exe or ""

    return executable_path.startswith(TEMPORARY_EXECUTION_PATHS)


def filter_temp_path_processes(processes: list[ProcessInfo]) -> list[ProcessInfo]:
    """Return processes running from common temporary execution paths."""
    return [
        process
        for process in processes
        if is_process_running_from_temp_path(process)
    ]


def filter_high_resource_processes(
    processes: list[ProcessInfo],
    cpu_threshold: float = 80.0,
    memory_threshold: float = 80.0,
) -> list[ProcessInfo]:
    """
    Return processes with high CPU or memory usage.

    High resource usage is not automatically malicious, but it can support
    investigation when combined with other suspicious indicators.
    """
    return [
        process
        for process in processes
        if process.cpu_percent >= cpu_threshold
        or process.memory_percent >= memory_threshold
    ]


def filter_processes_by_keywords(
    processes: list[ProcessInfo],
    suspicious_keywords: list[str],
) -> list[ProcessInfo]:
    """
    Return processes whose command line contains suspicious keywords.

    This is defensive keyword matching only. Tools like curl, wget, nmap,
    or python can be legitimate, so these findings should be treated as
    investigation signals, not automatic proof of compromise.
    """
    matched_processes: list[ProcessInfo] = []

    normalized_keywords = [
        keyword.lower().strip()
        for keyword in suspicious_keywords
        if keyword.strip()
    ]

    for process in processes:
        command_text = " ".join(
            [
                process.name,
                process.exe or "",
                " ".join(process.cmdline),
            ]
        ).lower()

        if any(keyword in command_text for keyword in normalized_keywords):
            matched_processes.append(process)

    return matched_processes


def processes_to_dicts(processes: list[ProcessInfo]) -> list[dict[str, Any]]:
    """Convert a list of ProcessInfo objects to dictionaries."""
    return [process.to_dict() for process in processes]
