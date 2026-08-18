from sentinellite.collectors.network import NetworkConnection
from sentinellite.models.security_event import SecurityEvent
from sentinellite.normalization.network import network_connection_to_security_event


def create_connection(**overrides) -> NetworkConnection:
    values = {
        "fd": 9,
        "family": 2,
        "type": 1,
        "local_address": "127.0.0.1",
        "local_port": 5000,
        "remote_address": "127.0.0.1",
        "remote_port": 5432,
        "status": "ESTABLISHED",
        "pid": 4242,
        "process_name": "python3",
    }
    values.update(overrides)
    return NetworkConnection(**values)


def test_network_connection_with_local_and_remote_endpoint_has_clear_message() -> None:
    connection = create_connection()

    event = network_connection_to_security_event(connection)

    assert event.message == (
        "Observed network connection from 127.0.0.1:5000 to 127.0.0.1:5432"
    )
    assert event.raw_data is None


def test_listening_connection_without_remote_endpoint_is_described_safely() -> None:
    connection = create_connection(
        local_address="0.0.0.0",
        local_port=22,
        remote_address=None,
        remote_port=None,
        status="LISTEN",
    )

    event = network_connection_to_security_event(connection)

    assert event.message == "Observed network connection at 0.0.0.0:22 with no remote endpoint"
    assert event.evidence["remote_address"] is None
    assert event.evidence["remote_port"] is None


def test_network_connection_without_process_identity_preserves_missing_values() -> None:
    connection = create_connection(pid=None, process_name=None)

    event = network_connection_to_security_event(connection)

    assert event.evidence["pid"] is None
    assert event.evidence["process_name"] is None


def test_network_connection_event_preserves_evidence_and_metadata() -> None:
    connection = create_connection()

    event = network_connection_to_security_event(connection)

    assert isinstance(event, SecurityEvent)
    assert event.source == "network"
    assert event.event_type == "network_connection_observation"
    assert event.severity == "info"
    assert event.evidence == {
        "fd": 9,
        "family": 2,
        "type": 1,
        "local_address": "127.0.0.1",
        "local_port": 5000,
        "remote_address": "127.0.0.1",
        "remote_port": 5432,
        "status": "ESTABLISHED",
        "pid": 4242,
        "process_name": "python3",
    }
    assert event.raw_data is None
