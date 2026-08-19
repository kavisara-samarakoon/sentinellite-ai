import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinellite.baseline.file_integrity import (
    BASELINE_VERSION,
    FileIntegrityBaseline,
    FileIntegrityBaselineEntry,
    create_baseline_from_records,
    load_baseline,
    save_baseline,
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


def test_save_baseline_writes_json_file(tmp_path: Path) -> None:
    baseline = create_baseline_from_records(
        [create_record()],
        created_at="2026-08-19T10:30:00+00:00",
    )
    baseline_path = tmp_path / "baseline.json"

    written_path = save_baseline(baseline, baseline_path)

    assert written_path == baseline_path
    assert json.loads(baseline_path.read_text(encoding="utf-8")) == baseline.to_dict()
    assert '\n  "version"' in baseline_path.read_text(encoding="utf-8")


def test_load_baseline_reads_saved_baseline(tmp_path: Path) -> None:
    baseline = create_baseline_from_records(
        [create_record()],
        created_at="2026-08-19T10:30:00+00:00",
    )
    baseline_path = save_baseline(baseline, tmp_path / "baseline.json")

    loaded_baseline = load_baseline(baseline_path)

    assert loaded_baseline == baseline


def test_save_load_round_trip_preserves_entries(tmp_path: Path) -> None:
    baseline = FileIntegrityBaseline(
        version=BASELINE_VERSION,
        created_at="2026-08-19T10:30:00+00:00",
        entries=[
            FileIntegrityBaselineEntry(
                path="/selected/config.txt",
                exists=True,
                is_file=True,
                size_bytes=128,
                modified_time_epoch=1_700_000_000.25,
                sha256="a" * 64,
            ),
            FileIntegrityBaselineEntry(
                path="/selected/missing.txt",
                exists=False,
                is_file=False,
                size_bytes=None,
                modified_time_epoch=None,
                sha256=None,
                error="Path does not exist",
            ),
        ],
    )

    loaded_baseline = load_baseline(save_baseline(baseline, tmp_path / "baseline.json"))

    assert loaded_baseline.entries == baseline.entries


def test_load_baseline_raises_for_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing-baseline.json"

    with pytest.raises(FileNotFoundError):
        load_baseline(missing_path)


def test_load_baseline_rejects_invalid_json_object_shape(tmp_path: Path) -> None:
    baseline_path = tmp_path / "invalid-shape.json"
    baseline_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="Baseline JSON must contain an object"):
        load_baseline(baseline_path)


def test_load_baseline_rejects_unsupported_version(tmp_path: Path) -> None:
    baseline_path = tmp_path / "unsupported-version.json"
    baseline_path.write_text(
        json.dumps(
            {
                "version": BASELINE_VERSION + 1,
                "created_at": "2026-08-19T10:30:00+00:00",
                "entries": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported baseline version"):
        load_baseline(baseline_path)


def test_save_baseline_does_not_create_or_modify_monitored_files(tmp_path: Path) -> None:
    monitored_path = tmp_path / "monitored.txt"
    monitored_path.write_text("original content", encoding="utf-8")
    missing_monitored_path = tmp_path / "missing-monitored.txt"
    original_stat = monitored_path.stat()
    baseline = FileIntegrityBaseline(
        version=BASELINE_VERSION,
        created_at="2026-08-19T10:30:00+00:00",
        entries=[
            FileIntegrityBaselineEntry(
                path=str(monitored_path),
                exists=True,
                is_file=True,
                size_bytes=original_stat.st_size,
                modified_time_epoch=original_stat.st_mtime,
                sha256="a" * 64,
            ),
            FileIntegrityBaselineEntry(
                path=str(missing_monitored_path),
                exists=False,
                is_file=False,
                size_bytes=None,
                modified_time_epoch=None,
                sha256=None,
            ),
        ],
    )

    save_baseline(baseline, tmp_path / "baseline.json")

    assert monitored_path.read_text(encoding="utf-8") == "original content"
    current_stat = monitored_path.stat()
    assert current_stat.st_size == original_stat.st_size
    assert current_stat.st_mtime_ns == original_stat.st_mtime_ns
    assert current_stat.st_mode == original_stat.st_mode
    assert not missing_monitored_path.exists()


def test_save_and_load_do_not_collect_or_hash_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def reject_operation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Baseline persistence must not collect or hash monitored files.")

    monkeypatch.setattr(
        "sentinellite.collectors.file_integrity.collect_file_integrity",
        reject_operation,
    )
    monkeypatch.setattr(
        "sentinellite.collectors.file_integrity.calculate_sha256",
        reject_operation,
    )
    baseline = create_baseline_from_records(
        [create_record()],
        created_at="2026-08-19T10:30:00+00:00",
    )

    baseline_path = save_baseline(baseline, tmp_path / "baseline.json")

    assert load_baseline(baseline_path) == baseline
