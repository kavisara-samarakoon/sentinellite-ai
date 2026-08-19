from datetime import UTC, datetime

import pytest

from sentinellite.baseline.file_integrity import (
    BASELINE_VERSION,
    FileIntegrityBaseline,
    FileIntegrityBaselineEntry,
    create_baseline_from_records,
)
from sentinellite.collectors.file_integrity import FileIntegrityRecord


def create_record() -> FileIntegrityRecord:
    return FileIntegrityRecord(
        path="/selected/config.txt",
        exists=True,
        is_file=True,
        size_bytes=128,
        modified_time_epoch=1_700_000_000.25,
        sha256="a" * 64,
        error=None,
    )


def test_baseline_entry_to_dict_from_dict_round_trip() -> None:
    entry = FileIntegrityBaselineEntry(
        path="/selected/config.txt",
        exists=True,
        is_file=True,
        size_bytes=128,
        modified_time_epoch=1_700_000_000.25,
        sha256="a" * 64,
        error=None,
    )

    assert FileIntegrityBaselineEntry.from_dict(entry.to_dict()) == entry


def test_baseline_to_dict_from_dict_round_trip() -> None:
    baseline = FileIntegrityBaseline(
        version=BASELINE_VERSION,
        created_at="2026-08-19T10:30:00+00:00",
        entries=[
            FileIntegrityBaselineEntry(
                path="/selected/missing.txt",
                exists=False,
                is_file=False,
                size_bytes=None,
                modified_time_epoch=None,
                sha256=None,
                error="Path does not exist",
            )
        ],
    )

    assert FileIntegrityBaseline.from_dict(baseline.to_dict()) == baseline


def test_create_baseline_from_records_converts_records() -> None:
    record = create_record()

    baseline = create_baseline_from_records(
        [record],
        created_at="2026-08-19T10:30:00+00:00",
    )

    assert baseline.version == BASELINE_VERSION
    assert baseline.entries == [
        FileIntegrityBaselineEntry(
            path=record.path,
            exists=record.exists,
            is_file=record.is_file,
            size_bytes=record.size_bytes,
            modified_time_epoch=record.modified_time_epoch,
            sha256=record.sha256,
            error=record.error,
        )
    ]


def test_create_baseline_uses_supplied_created_at() -> None:
    created_at = "2026-08-19T10:30:00+00:00"

    baseline = create_baseline_from_records([], created_at=created_at)

    assert baseline.created_at == created_at


def test_create_baseline_auto_generates_utc_created_at() -> None:
    before = datetime.now(UTC)

    baseline = create_baseline_from_records([])

    after = datetime.now(UTC)
    generated_at = datetime.fromisoformat(baseline.created_at)
    assert generated_at.tzinfo == UTC
    assert before <= generated_at <= after


def test_baseline_from_dict_rejects_unsupported_version() -> None:
    data = {
        "version": BASELINE_VERSION + 1,
        "created_at": "2026-08-19T10:30:00+00:00",
        "entries": [],
    }

    with pytest.raises(ValueError, match="Unsupported baseline version"):
        FileIntegrityBaseline.from_dict(data)


@pytest.mark.parametrize("missing_field", ["version", "created_at", "entries"])
def test_baseline_from_dict_rejects_missing_required_fields(missing_field: str) -> None:
    data: dict[str, object] = {
        "version": BASELINE_VERSION,
        "created_at": "2026-08-19T10:30:00+00:00",
        "entries": [],
    }
    del data[missing_field]

    with pytest.raises(ValueError, match="Missing required baseline fields"):
        FileIntegrityBaseline.from_dict(data)


def test_baseline_entry_from_dict_rejects_missing_required_fields() -> None:
    data = create_baseline_from_records(
        [create_record()],
        created_at="2026-08-19T10:30:00+00:00",
    ).entries[0].to_dict()
    del data["path"]

    with pytest.raises(ValueError, match="Missing required baseline entry fields"):
        FileIntegrityBaselineEntry.from_dict(data)


@pytest.mark.parametrize(
    "invalid_entries",
    [None, {}, "not-a-list", ["not-an-object"]],
)
def test_baseline_from_dict_rejects_invalid_entries(invalid_entries: object) -> None:
    data = {
        "version": BASELINE_VERSION,
        "created_at": "2026-08-19T10:30:00+00:00",
        "entries": invalid_entries,
    }

    with pytest.raises(ValueError, match="[Bb]aseline entr"):
        FileIntegrityBaseline.from_dict(data)


def test_create_baseline_from_records_performs_no_filesystem_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_operation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("The baseline model must not access the filesystem or hash files.")

    monkeypatch.setattr("builtins.open", reject_operation)
    monkeypatch.setattr("pathlib.Path.stat", reject_operation)
    monkeypatch.setattr("hashlib.sha256", reject_operation)

    baseline = create_baseline_from_records(
        [create_record()],
        created_at="2026-08-19T10:30:00+00:00",
    )

    assert baseline.entries[0].path == "/selected/config.txt"
