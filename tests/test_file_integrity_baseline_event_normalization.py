import pytest

from sentinellite.baseline.file_integrity import (
    COMPARISON_CHANGED,
    COMPARISON_MISSING_NOW,
    COMPARISON_NOT_IN_BASELINE,
    COMPARISON_UNCHANGED,
    FileIntegrityBaselineComparison,
    FileIntegrityBaselineEntry,
)
from sentinellite.models.security_event import SecurityEvent
from sentinellite.normalization.file_integrity_baseline import (
    file_integrity_baseline_comparison_to_security_event,
)


def create_entry(
    path: str = "README.md",
    *,
    exists: bool = True,
    is_file: bool = True,
    size_bytes: int | None = 100,
    modified_time_epoch: float | None = 1_700_000_000.0,
    sha256: str | None = "a" * 64,
    error: str | None = None,
) -> FileIntegrityBaselineEntry:
    return FileIntegrityBaselineEntry(
        path=path,
        exists=exists,
        is_file=is_file,
        size_bytes=size_bytes,
        modified_time_epoch=modified_time_epoch,
        sha256=sha256,
        error=error,
    )


def create_comparison(
    *,
    status: str = COMPARISON_UNCHANGED,
    changed_fields: list[str] | None = None,
    baseline_entry: FileIntegrityBaselineEntry | None = None,
    current_entry: FileIntegrityBaselineEntry | None = None,
    message: str = "File matches baseline: README.md",
) -> FileIntegrityBaselineComparison:
    return FileIntegrityBaselineComparison(
        path="README.md",
        status=status,
        changed_fields=[] if changed_fields is None else changed_fields,
        baseline_entry=create_entry() if baseline_entry is None else baseline_entry,
        current_entry=create_entry() if current_entry is None else current_entry,
        message=message,
    )


def test_changed_comparison_becomes_security_event() -> None:
    baseline_entry = create_entry()
    current_entry = create_entry(
        size_bytes=120,
        modified_time_epoch=1_700_000_001.0,
        sha256="b" * 64,
    )
    comparison = create_comparison(
        status=COMPARISON_CHANGED,
        changed_fields=["size_bytes", "modified_time_epoch", "sha256"],
        baseline_entry=baseline_entry,
        current_entry=current_entry,
        message="File changed compared with baseline: README.md",
    )

    event = file_integrity_baseline_comparison_to_security_event(comparison)

    assert isinstance(event, SecurityEvent)
    assert event.source == "file_integrity_baseline"
    assert event.event_type == "file_integrity_baseline_comparison"
    assert event.severity == "info"
    assert event.message == comparison.message
    assert event.evidence == {
        "path": "README.md",
        "status": COMPARISON_CHANGED,
        "changed_fields": ["size_bytes", "modified_time_epoch", "sha256"],
        "baseline_entry": baseline_entry.to_dict(),
        "current_entry": current_entry.to_dict(),
    }
    assert event.raw_data is None


def test_unchanged_comparison_becomes_security_event() -> None:
    comparison = create_comparison()

    event = file_integrity_baseline_comparison_to_security_event(comparison)

    assert isinstance(event, SecurityEvent)
    assert event.evidence["status"] == COMPARISON_UNCHANGED
    assert event.evidence["changed_fields"] == []
    assert event.message == "File matches baseline: README.md"


def test_missing_now_comparison_becomes_security_event() -> None:
    current_entry = create_entry(
        exists=False,
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
    )
    comparison = create_comparison(
        status=COMPARISON_MISSING_NOW,
        changed_fields=["exists"],
        current_entry=current_entry,
        message="File missing compared with baseline: README.md",
    )

    event = file_integrity_baseline_comparison_to_security_event(comparison)

    assert event.evidence["status"] == COMPARISON_MISSING_NOW
    assert event.evidence["current_entry"] == current_entry.to_dict()
    assert event.message == comparison.message


def test_not_in_baseline_comparison_preserves_none_baseline_entry() -> None:
    comparison = FileIntegrityBaselineComparison(
        path="README.md",
        status=COMPARISON_NOT_IN_BASELINE,
        changed_fields=[],
        baseline_entry=None,
        current_entry=create_entry(),
        message="File was not present in the baseline: README.md",
    )

    event = file_integrity_baseline_comparison_to_security_event(comparison)

    assert event.evidence["baseline_entry"] is None
    assert event.evidence["current_entry"] == comparison.current_entry.to_dict()
    assert event.evidence["status"] == COMPARISON_NOT_IN_BASELINE


def test_changed_fields_are_copied() -> None:
    comparison = create_comparison(
        status=COMPARISON_CHANGED,
        changed_fields=["sha256"],
        message="File changed compared with baseline: README.md",
    )

    event = file_integrity_baseline_comparison_to_security_event(comparison)
    event_changed_fields = event.evidence["changed_fields"]

    assert event_changed_fields == ["sha256"]
    assert event_changed_fields is not comparison.changed_fields


def test_normalization_performs_no_filesystem_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_operation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Baseline event normalization must not access or hash files.")

    monkeypatch.setattr("builtins.open", reject_operation)
    monkeypatch.setattr("pathlib.Path.open", reject_operation)
    monkeypatch.setattr("pathlib.Path.stat", reject_operation)
    monkeypatch.setattr("pathlib.Path.unlink", reject_operation)
    monkeypatch.setattr("hashlib.sha256", reject_operation)
    monkeypatch.setattr(
        "sentinellite.collectors.file_integrity.collect_file_integrity",
        reject_operation,
    )
    monkeypatch.setattr(
        "sentinellite.collectors.file_integrity.calculate_sha256",
        reject_operation,
    )

    event = file_integrity_baseline_comparison_to_security_event(create_comparison())

    assert event.source == "file_integrity_baseline"
