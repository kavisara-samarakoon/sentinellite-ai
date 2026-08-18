from sentinellite.collectors.file_integrity import FileIntegrityRecord
from sentinellite.models.security_event import SecurityEvent
from sentinellite.normalization.file_integrity import (
    file_integrity_record_to_security_event,
)


def test_existing_file_record_preserves_evidence_and_event_metadata() -> None:
    record = FileIntegrityRecord(
        path="/selected/config.txt",
        exists=True,
        is_file=True,
        size_bytes=128,
        modified_time_epoch=1_725_000_000.5,
        sha256="a" * 64,
        error=None,
    )

    event = file_integrity_record_to_security_event(record)

    assert isinstance(event, SecurityEvent)
    assert event.source == "file_integrity"
    assert event.event_type == "file_integrity_observation"
    assert event.severity == "info"
    assert event.message == "Observed file integrity state for /selected/config.txt"
    assert event.evidence == {
        "path": "/selected/config.txt",
        "exists": True,
        "is_file": True,
        "size_bytes": 128,
        "modified_time_epoch": 1_725_000_000.5,
        "sha256": "a" * 64,
        "error": None,
    }
    assert event.raw_data is None


def test_missing_file_record_has_defensive_message() -> None:
    record = FileIntegrityRecord(
        path="/selected/missing.txt",
        exists=False,
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
        error="Path does not exist: /selected/missing.txt",
    )

    event = file_integrity_record_to_security_event(record)

    assert event.message == "Observed missing file at /selected/missing.txt"
    assert event.evidence["exists"] is False
    assert event.evidence["error"] == "Path does not exist: /selected/missing.txt"
    assert event.raw_data is None


def test_directory_record_has_defensive_message() -> None:
    record = FileIntegrityRecord(
        path="/selected/directory",
        exists=True,
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
        error=None,
    )

    event = file_integrity_record_to_security_event(record)

    assert event.message == (
        "Observed directory path during file integrity check: /selected/directory"
    )
    assert event.evidence["is_file"] is False
    assert event.evidence["sha256"] is None
    assert event.raw_data is None


def test_read_error_record_reports_check_error_without_overstatement() -> None:
    record = FileIntegrityRecord(
        path="/selected/unreadable.txt",
        exists=True,
        is_file=True,
        size_bytes=64,
        modified_time_epoch=1_725_000_001.0,
        sha256=None,
        error="Unable to read file: permission denied",
    )

    event = file_integrity_record_to_security_event(record)

    assert event.message == (
        "File integrity check had an error for /selected/unreadable.txt: "
        "Unable to read file: permission denied"
    )
    assert event.severity == "info"
    assert event.evidence["error"] == "Unable to read file: permission denied"
    assert event.raw_data is None


def test_inspection_error_is_not_described_as_a_confirmed_missing_file() -> None:
    record = FileIntegrityRecord(
        path="/selected/restricted.txt",
        exists=False,
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
        error="Unable to inspect path: permission denied",
    )

    event = file_integrity_record_to_security_event(record)

    assert event.message == (
        "File integrity check had an error for /selected/restricted.txt: "
        "Unable to inspect path: permission denied"
    )
    assert "missing file" not in event.message.lower()
    assert event.evidence["error"] == "Unable to inspect path: permission denied"
