from __future__ import annotations

from sentinellite.collectors.network import NetworkConnection
from sentinellite.models.security_event import SecurityEvent, create_security_event


def _format_endpoint(address: str | None, port: int | None) -> str:
    """Format collected endpoint fields without resolving or inferring an address."""
    if address is None:
        return "unknown local endpoint"

    if port is None:
        return f"{address} (port unavailable)"

    return f"{address}:{port}"


def network_connection_to_security_event(connection: NetworkConnection) -> SecurityEvent:
    """Convert a collected network connection into a read-only security observation."""
    local_endpoint = _format_endpoint(connection.local_address, connection.local_port)

    if connection.remote_address is None:
        message = f"Observed network connection at {local_endpoint} with no remote endpoint"
    else:
        remote_endpoint = _format_endpoint(connection.remote_address, connection.remote_port)
        message = f"Observed network connection from {local_endpoint} to {remote_endpoint}"

    return create_security_event(
        source="network",
        event_type="network_connection_observation",
        severity="info",
        message=message,
        evidence={
            "fd": connection.fd,
            "family": connection.family,
            "type": connection.type,
            "local_address": connection.local_address,
            "local_port": connection.local_port,
            "remote_address": connection.remote_address,
            "remote_port": connection.remote_port,
            "status": connection.status,
            "pid": connection.pid,
            "process_name": connection.process_name,
        },
        raw_data=None,
    )
