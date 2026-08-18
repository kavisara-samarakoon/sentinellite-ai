import hashlib
import re
from pathlib import Path

import pytest

from sentinellite.collectors.file_integrity import (
    FileIntegrityRecord,
    calculate_sha256,
    collect_file_integrity,
)


def test_collect_file_integrity_hashes_existing_file(tmp_path: Path) -> None:
    file_path = tmp_path / "observed.txt"
    file_content = b"SentinelLite file integrity test\n"
    file_path.write_bytes(file_content)

    records = collect_file_integrity([file_path])

    assert len(records) == 1
    record = records[0]
    assert isinstance(record, FileIntegrityRecord)
    assert record.path == str(file_path)
    assert record.exists is True
    assert record.is_file is True
    assert record.size_bytes == len(file_content)
    assert isinstance(record.modified_time_epoch, float)
    assert record.sha256 == hashlib.sha256(file_content).hexdigest()
    assert record.error is None


def test_calculate_sha256_returns_lowercase_sha256_format(tmp_path: Path) -> None:
    file_path = tmp_path / "hash-format.txt"
    file_path.write_text("format test", encoding="utf-8")

    result = calculate_sha256(file_path)

    assert re.fullmatch(r"[0-9a-f]{64}", result)


def test_collect_file_integrity_records_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.txt"

    records = collect_file_integrity([missing_path])

    assert records == [
        FileIntegrityRecord(
            path=str(missing_path),
            exists=False,
            is_file=False,
            size_bytes=None,
            modified_time_epoch=None,
            sha256=None,
            error=f"Path does not exist: {missing_path}",
        )
    ]


def test_collect_file_integrity_does_not_hash_directory(tmp_path: Path) -> None:
    directory_path = tmp_path / "observed-directory"
    directory_path.mkdir()

    records = collect_file_integrity([directory_path])

    assert records == [
        FileIntegrityRecord(
            path=str(directory_path),
            exists=True,
            is_file=False,
            size_bytes=None,
            modified_time_epoch=None,
            sha256=None,
            error=None,
        )
    ]


def test_collect_file_integrity_handles_multiple_paths(tmp_path: Path) -> None:
    first_path = tmp_path / "first.txt"
    second_path = tmp_path / "second.txt"
    missing_path = tmp_path / "missing.txt"
    first_path.write_text("first", encoding="utf-8")
    second_path.write_text("second", encoding="utf-8")

    records = collect_file_integrity([first_path, str(second_path), missing_path])

    assert [record.path for record in records] == [
        str(first_path),
        str(second_path),
        str(missing_path),
    ]
    assert [record.exists for record in records] == [True, True, False]
    assert records[0].sha256 == hashlib.sha256(b"first").hexdigest()
    assert records[1].sha256 == hashlib.sha256(b"second").hexdigest()
    assert records[2].sha256 is None


def test_collect_file_integrity_handles_read_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "unreadable.txt"
    file_path.write_text("cannot read", encoding="utf-8")

    def raise_permission_error(_path: Path) -> str:
        raise PermissionError("read denied for test")

    monkeypatch.setattr(
        "sentinellite.collectors.file_integrity.calculate_sha256",
        raise_permission_error,
    )

    records = collect_file_integrity([file_path])

    assert len(records) == 1
    record = records[0]
    assert record.exists is True
    assert record.is_file is True
    assert record.size_bytes == len("cannot read")
    assert record.modified_time_epoch is not None
    assert record.sha256 is None
    assert record.error == "Unable to read file: read denied for test"
