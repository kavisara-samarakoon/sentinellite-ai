import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.detection.rules import DEFAULT_RULES
from sentinellite.models.security_event import SecurityEvent, create_security_event


def create_network_event(**evidence_overrides) -> SecurityEvent:
    evidence = {
        "fd": 7,
        "family": 2,
        "type": 1,
        "local_address": "127.0.0.1",
        "local_port": 5000,
        "remote_address": None,
        "remote_port": None,
        "status": "NONE",
        "pid": 42,
        "process_name": "worker",
    }
    evidence.update(evidence_overrides)

    return create_security_event(
        source="network",
        event_type="network_connection_observation",
        severity="info",
        message="Observed network connection for rule testing",
        evidence=evidence,
    )


def test_net_001_matches_listening_service_on_unusual_port() -> None:
    event = create_network_event(status="LISTEN", local_port=8080)

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["NET-001"]
    assert matches[0].rule_name == "Listening Service on Unusual Port"
    assert matches[0].category == "network_exposure"
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 55


@pytest.mark.parametrize("local_port", [22, 53, 80, 443])
def test_net_001_does_not_match_common_listening_ports(local_port: int) -> None:
    event = create_network_event(status="LISTEN", local_port=local_port)

    assert detect_event(event) == []


def test_net_001_does_not_match_non_listening_connection() -> None:
    event = create_network_event(status="ESTABLISHED", local_port=8080)

    assert detect_event(event) == []


def test_net_002_matches_external_remote_connection() -> None:
    event = create_network_event(
        status="ESTABLISHED",
        remote_address="8.8.8.8",
        remote_port=443,
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["NET-002"]
    assert matches[0].rule_name == "External Remote Connection"
    assert matches[0].category == "network_connection"
    assert matches[0].severity == "low"
    assert matches[0].base_score == 35


@pytest.mark.parametrize(
    "remote_address",
    [None, "", "127.0.0.1", "10.1.2.3", "172.16.5.4", "192.168.1.10"],
)
def test_net_002_does_not_match_empty_loopback_or_private_address(
    remote_address: str | None,
) -> None:
    event = create_network_event(
        status="ESTABLISHED",
        remote_address=remote_address,
        remote_port=443,
    )

    assert detect_event(event) == []


def test_net_002_does_not_match_invalid_remote_address() -> None:
    event = create_network_event(remote_address="not-an-ip", remote_port=443)

    assert detect_event(event) == []


@pytest.mark.parametrize("remote_port", [4444, 1337, 31337, 6667])
def test_net_003_matches_ports_designated_for_investigation(remote_port: int) -> None:
    event = create_network_event(
        status="ESTABLISHED",
        remote_address="192.168.1.50",
        remote_port=remote_port,
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["NET-003"]
    assert matches[0].rule_name == "Suspicious Remote Port"
    assert matches[0].category == "network_behavior"
    assert matches[0].severity == "low"
    assert matches[0].base_score == 40


def test_net_003_does_not_match_ordinary_remote_port() -> None:
    event = create_network_event(remote_address="192.168.1.50", remote_port=443)

    assert detect_event(event) == []


def test_network_rules_are_registered_without_changing_existing_rules() -> None:
    rule_ids = [rule.rule_id for rule in DEFAULT_RULES]

    assert rule_ids == [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "PROC-001",
        "PROC-002",
        "PROC-003",
        "NET-001",
        "NET-002",
        "NET-003",
    ]
