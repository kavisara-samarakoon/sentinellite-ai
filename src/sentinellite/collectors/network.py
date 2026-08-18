from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psutil


@dataclass(frozen=True, slots=True)
class NetworkConnection:
    """Read-only information about an active internet connection."""

    fd: int
    family: int
    type: int
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    status: str
    pid: int | None
    process_name: str | None


def _split_address(address: Any) -> tuple[str | None, int | None]:
    """Return an address and port without assuming an endpoint is present."""
    if not address:
        return None, None

    host = getattr(address, "ip", None)
    port = getattr(address, "port", None)

    if host is None and isinstance(address, (tuple, list)):
        host = address[0] if address else None
        port = address[1] if len(address) > 1 else None

    normalized_host = str(host) if host is not None else None
    normalized_port = int(port) if port is not None else None
    return normalized_host, normalized_port


def _get_process_name(pid: int | None) -> str | None:
    """Look up a process name when permissions and process lifetime allow it."""
    if pid is None:
        return None

    try:
        return psutil.Process(pid).name()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def collect_network_connections() -> list[NetworkConnection]:
    """Collect active internet connections without changing network state."""
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return []

    results: list[NetworkConnection] = []

    for connection in connections:
        local_address, local_port = _split_address(connection.laddr)
        remote_address, remote_port = _split_address(connection.raddr)
        pid = int(connection.pid) if connection.pid is not None else None

        results.append(
            NetworkConnection(
                fd=int(connection.fd),
                family=int(connection.family),
                type=int(connection.type),
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                status=str(connection.status),
                pid=pid,
                process_name=_get_process_name(pid),
            )
        )

    return results
