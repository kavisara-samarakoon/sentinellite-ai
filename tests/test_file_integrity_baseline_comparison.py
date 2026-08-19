import json

import pytest

from sentinellite.baseline.file_integrity import (
    BASELINE_VERSION,
    COMPARISON_APPEARED_NOW,
    COMPARISON_CHANGED,
    COMPARISON_CURRENT_ERROR,
    COMPARISON_MISSING_NOW,
    COMPARISON_NOT_IN_BASELINE,
    COMPARISON_TYPE_CHANGED,
    COMPARISON_UNCHANGED,
    FileIntegrityBaseline,
    FileIntegrityBaselineEntry,
    compare_record_to_baseline,
    compare_records_to_baseline,
)
from sentinellite.collectors.file_integrity import FileIntegrityRecord


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


def create_record(
    path: str = "README.md",
    *,
    exists: bool = True,
    is_file: bool = True,
    size_bytes: int | None = 100,
    modified_time_epoch: float | None = 1_700_000_000.0,
    sha256: str | None = "a" * 64,
    error: str | None = None,
) -> FileIntegrityRecord:
    return FileIntegrityRecord(
        path=path,
        exists=exists,
        is_file=is_file,
        size_bytes=size_bytes,
        modified_time_epoch=modified_time_epoch,
        sha256=sha256,
        error=error,
    )


def create_baseline(
    entries: list[FileIntegrityBaselineEntry] | None = None,
) -> FileIntegrityBaseline:
    return FileIntegrityBaseline(
        version=BASELINE_VERSION,
        created_at="2026-08-19T10:30:00+00:00",
        entries=[create_entry()] if entries is None else entries,
    )


def test_compare_unchanged_file() -> None:
    result = compare_record_to_baseline(create_record(), create_baseline())

    assert result.status == COMPARISON_UNCHANGED
    assert result.changed_fields == []
    assert result.message == "File matches baseline: README.md"


def test_compare_changed_hash() -> None:
    result = compare_record_to_baseline(
        create_record(sha256="b" * 64),
        create_baseline(),
    )

    assert result.status == COMPARISON_CHANGED
    assert result.changed_fields == ["sha256"]


def test_compare_changed_size() -> None:
    result = compare_record_to_baseline(
        create_record(size_bytes=101),
        create_baseline(),
    )

    assert result.status == COMPARISON_CHANGED
    assert result.changed_fields == ["size_bytes"]


def test_compare_changed_modified_time() -> None:
    result = compare_record_to_baseline(
        create_record(modified_time_epoch=1_700_000_001.0),
        create_baseline(),
    )

    assert result.status == COMPARISON_CHANGED
    assert result.changed_fields == ["modified_time_epoch"]


def test_compare_multiple_changed_fields() -> None:
    result = compare_record_to_baseline(
        create_record(
            size_bytes=101,
            modified_time_epoch=1_700_000_001.0,
            sha256="b" * 64,
        ),
        create_baseline(),
    )

    assert result.status == COMPARISON_CHANGED
    assert result.changed_fields == ["size_bytes", "modified_time_epoch", "sha256"]


def test_compare_file_missing_now() -> None:
    result = compare_record_to_baseline(
        create_record(
            exists=False,
            is_file=False,
            size_bytes=None,
            modified_time_epoch=None,
            sha256=None,
            error="Path does not exist: README.md",
        ),
        create_baseline(),
    )

    assert result.status == COMPARISON_MISSING_NOW
    assert result.changed_fields == ["exists"]
    assert result.current_entry.error == "Path does not exist: README.md"
    assert result.message == "File missing compared with baseline: README.md"


def test_compare_file_appeared_now() -> None:
    baseline = create_baseline(
        [
            create_entry(
                exists=False,
                is_file=False,
                size_bytes=None,
                modified_time_epoch=None,
                sha256=None,
            )
        ]
    )

    result = compare_record_to_baseline(create_record(), baseline)

    assert result.status == COMPARISON_APPEARED_NOW
    assert result.changed_fields == ["exists"]


def test_compare_path_not_in_baseline() -> None:
    result = compare_record_to_baseline(
        create_record(path="new-file.txt"),
        create_baseline([]),
    )

    assert result.status == COMPARISON_NOT_IN_BASELINE
    assert result.changed_fields == []
    assert result.baseline_entry is None
    assert result.message == "File was not present in the baseline: new-file.txt"


def test_compare_file_type_changed() -> None:
    result = compare_record_to_baseline(
        create_record(
            is_file=False,
            size_bytes=None,
            modified_time_epoch=None,
            sha256=None,
        ),
        create_baseline(),
    )

    assert result.status == COMPARISON_TYPE_CHANGED
    assert result.changed_fields == ["is_file"]


def test_compare_current_error() -> None:
    result = compare_record_to_baseline(
        create_record(error="Unable to inspect selected path"),
        create_baseline(),
    )

    assert result.status == COMPARISON_CURRENT_ERROR
    assert result.changed_fields == ["error"]
    assert result.message == "File integrity check had an error for README.md"


def test_duplicate_baseline_paths_raise_value_error() -> None:
    baseline = create_baseline([create_entry(), create_entry()])

    with pytest.raises(ValueError, match="Duplicate path.*README.md"):
        compare_record_to_baseline(create_record(), baseline)

    with pytest.raises(ValueError, match="Duplicate path.*README.md"):
        compare_records_to_baseline([create_record()], baseline)


def test_compare_records_preserves_input_order() -> None:
    records = [
        create_record(path="third.txt"),
        create_record(path="first.txt"),
        create_record(path="second.txt"),
    ]
    baseline = create_baseline(
        [
            create_entry(path="first.txt"),
            create_entry(path="second.txt"),
            create_entry(path="third.txt"),
        ]
    )

    results = compare_records_to_baseline(records, baseline)

    assert [result.path for result in results] == ["third.txt", "first.txt", "second.txt"]


def test_comparison_to_dict_is_json_friendly() -> None:
    result = compare_record_to_baseline(create_record(), create_baseline())

    data = result.to_dict()

    assert json.loads(json.dumps(data)) == data
    assert data["baseline_entry"] == create_entry().to_dict()
    assert data["current_entry"] == create_entry().to_dict()


def test_comparison_performs_no_filesystem_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_operation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Baseline comparison must not access or hash monitored files.")

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

    results = compare_records_to_baseline([create_record()], create_baseline())

    assert results[0].status == COMPARISON_UNCHANGED
