import socket
from types import SimpleNamespace

import psutil
import pytest

from sentinellite.collectors.network import NetworkConnection, collect_network_connections


def fake_connection(**overrides):
    values = {
        "fd": 7,
        "family": socket.AF_INET,
        "type": socket.SOCK_STREAM,
        "laddr": ("127.0.0.1", 8080),
        "raddr": ("192.0.2.10", 443),
        "status": "ESTABLISHED",
        "pid": 42,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_collect_network_connections_normalizes_safe_fields(monkeypatch):
    def fake_net_connections(*, kind):
        assert kind == "inet"
        return [fake_connection()]

    class FakeProcess:
        def __init__(self, pid):
            assert pid == 42

        def name(self):
            return "python"

    monkeypatch.setattr(
        "sentinellite.collectors.network.psutil.net_connections",
        fake_net_connections,
    )
    monkeypatch.setattr("sentinellite.collectors.network.psutil.Process", FakeProcess)

    connections = collect_network_connections()

    assert connections == [
        NetworkConnection(
            fd=7,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            local_address="127.0.0.1",
            local_port=8080,
            remote_address="192.0.2.10",
            remote_port=443,
            status="ESTABLISHED",
            pid=42,
            process_name="python",
        )
    ]


def test_collect_network_connections_handles_missing_addresses(monkeypatch):
    monkeypatch.setattr(
        "sentinellite.collectors.network.psutil.net_connections",
        lambda *, kind: [fake_connection(laddr=(), raddr=None, pid=None)],
    )

    connections = collect_network_connections()

    assert connections[0].local_address is None
    assert connections[0].local_port is None
    assert connections[0].remote_address is None
    assert connections[0].remote_port is None
    assert connections[0].pid is None
    assert connections[0].process_name is None


@pytest.mark.parametrize(
    "process_error",
    [
        psutil.AccessDenied(pid=42),
        psutil.NoSuchProcess(pid=42),
        psutil.ZombieProcess(pid=42),
    ],
)
def test_collect_network_connections_handles_unavailable_process_names(
    monkeypatch,
    process_error,
):
    monkeypatch.setattr(
        "sentinellite.collectors.network.psutil.net_connections",
        lambda *, kind: [fake_connection()],
    )

    def unavailable_process(_pid):
        raise process_error

    monkeypatch.setattr("sentinellite.collectors.network.psutil.Process", unavailable_process)

    connections = collect_network_connections()

    assert len(connections) == 1
    assert connections[0].pid == 42
    assert connections[0].process_name is None


@pytest.mark.parametrize(
    "collection_error",
    [
        psutil.AccessDenied(),
        psutil.NoSuchProcess(pid=42),
        psutil.ZombieProcess(pid=42),
    ],
)
def test_collect_network_connections_handles_collection_errors(
    monkeypatch,
    collection_error,
):
    def unavailable_connections(*, kind):
        raise collection_error

    monkeypatch.setattr(
        "sentinellite.collectors.network.psutil.net_connections",
        unavailable_connections,
    )

    assert collect_network_connections() == []
