from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinellite.collectors.file_integrity import FileIntegrityRecord

BASELINE_VERSION = 1

COMPARISON_UNCHANGED = "unchanged"
COMPARISON_CHANGED = "changed"
COMPARISON_MISSING_NOW = "missing_now"
COMPARISON_APPEARED_NOW = "appeared_now"
COMPARISON_NOT_IN_BASELINE = "not_in_baseline"
COMPARISON_TYPE_CHANGED = "type_changed"
COMPARISON_CURRENT_ERROR = "current_error"


def _missing_fields(data: Mapping[str, object], required_fields: set[str]) -> list[str]:
    return sorted(required_fields.difference(data))


@dataclass(frozen=True, slots=True)
class FileIntegrityBaselineEntry:
    """Stored file metadata from an authorized, read-only observation."""

    path: str
    exists: bool
    is_file: bool
    size_bytes: int | None
    modified_time_epoch: float | None
    sha256: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "exists": self.exists,
            "is_file": self.is_file,
            "size_bytes": self.size_bytes,
            "modified_time_epoch": self.modified_time_epoch,
            "sha256": self.sha256,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> FileIntegrityBaselineEntry:
        required_fields = {
            "path",
            "exists",
            "is_file",
            "size_bytes",
            "modified_time_epoch",
            "sha256",
        }
        missing = _missing_fields(data, required_fields)
        if missing:
            raise ValueError(f"Missing required baseline entry fields: {', '.join(missing)}")

        path = data["path"]
        exists = data["exists"]
        is_file = data["is_file"]
        size_bytes = data["size_bytes"]
        modified_time_epoch = data["modified_time_epoch"]
        sha256 = data["sha256"]
        error = data.get("error")

        if not isinstance(path, str):
            raise ValueError("Baseline entry path must be a string.")  # noqa: TRY004
        if not isinstance(exists, bool):
            raise ValueError("Baseline entry exists must be a boolean.")  # noqa: TRY004
        if not isinstance(is_file, bool):
            raise ValueError("Baseline entry is_file must be a boolean.")  # noqa: TRY004
        if size_bytes is not None and (
            not isinstance(size_bytes, int) or isinstance(size_bytes, bool)
        ):
            raise ValueError("Baseline entry size_bytes must be an integer or null.")
        if modified_time_epoch is not None and (
            not isinstance(modified_time_epoch, (int, float))
            or isinstance(modified_time_epoch, bool)
        ):
            raise ValueError("Baseline entry modified_time_epoch must be a number or null.")
        if sha256 is not None and not isinstance(sha256, str):
            raise ValueError("Baseline entry sha256 must be a string or null.")
        if error is not None and not isinstance(error, str):
            raise ValueError("Baseline entry error must be a string or null.")

        return cls(
            path=path,
            exists=exists,
            is_file=is_file,
            size_bytes=size_bytes,
            modified_time_epoch=(
                float(modified_time_epoch) if modified_time_epoch is not None else None
            ),
            sha256=sha256,
            error=error,
        )


@dataclass(frozen=True, slots=True)
class FileIntegrityBaseline:
    """Versioned file integrity observations that can be serialized safely."""

    version: int
    created_at: str
    entries: list[FileIntegrityBaselineEntry]

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> FileIntegrityBaseline:
        required_fields = {"version", "created_at", "entries"}
        missing = _missing_fields(data, required_fields)
        if missing:
            raise ValueError(f"Missing required baseline fields: {', '.join(missing)}")

        version = data["version"]
        if not isinstance(version, int) or isinstance(version, bool):
            raise ValueError("Baseline version must be an integer.")  # noqa: TRY004
        if version != BASELINE_VERSION:
            raise ValueError(f"Unsupported baseline version: {version}")

        created_at = data["created_at"]
        if not isinstance(created_at, str):
            raise ValueError("Baseline created_at must be a string.")  # noqa: TRY004

        entries_data = data["entries"]
        if not isinstance(entries_data, list):
            raise ValueError("Baseline entries must be a list.")  # noqa: TRY004

        entries: list[FileIntegrityBaselineEntry] = []
        for entry_data in entries_data:
            if not isinstance(entry_data, Mapping):
                raise ValueError("Each baseline entry must be an object.")  # noqa: TRY004
            entries.append(FileIntegrityBaselineEntry.from_dict(entry_data))

        return cls(version=version, created_at=created_at, entries=entries)


@dataclass(frozen=True, slots=True)
class FileIntegrityBaselineComparison:
    """Investigation-focused result from comparing one observation with a baseline."""

    path: str
    status: str
    changed_fields: list[str]
    baseline_entry: FileIntegrityBaselineEntry | None
    current_entry: FileIntegrityBaselineEntry
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "status": self.status,
            "changed_fields": list(self.changed_fields),
            "baseline_entry": (
                self.baseline_entry.to_dict() if self.baseline_entry is not None else None
            ),
            "current_entry": self.current_entry.to_dict(),
            "message": self.message,
        }


def create_baseline_from_records(
    records: Sequence[FileIntegrityRecord],
    created_at: str | None = None,
) -> FileIntegrityBaseline:
    """Convert existing read-only observations into an in-memory baseline model."""
    entries = [
        FileIntegrityBaselineEntry(
            path=record.path,
            exists=record.exists,
            is_file=record.is_file,
            size_bytes=record.size_bytes,
            modified_time_epoch=record.modified_time_epoch,
            sha256=record.sha256,
            error=record.error,
        )
        for record in records
    ]

    return FileIntegrityBaseline(
        version=BASELINE_VERSION,
        created_at=created_at if created_at is not None else datetime.now(UTC).isoformat(),
        entries=entries,
    )


def save_baseline(baseline: FileIntegrityBaseline, path: Path | str) -> Path:
    """Save a baseline as readable JSON at an explicitly supplied path."""
    baseline_path = Path(path)

    with baseline_path.open("w", encoding="utf-8") as file:
        json.dump(baseline.to_dict(), file, indent=2)

    return baseline_path


def load_baseline(path: Path | str) -> FileIntegrityBaseline:
    """Load and validate a baseline from an explicitly supplied JSON path."""
    baseline_path = Path(path)

    with baseline_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, Mapping):
        raise ValueError("Baseline JSON must contain an object.")  # noqa: TRY004

    return FileIntegrityBaseline.from_dict(data)


def _entry_from_record(record: FileIntegrityRecord) -> FileIntegrityBaselineEntry:
    return FileIntegrityBaselineEntry(
        path=record.path,
        exists=record.exists,
        is_file=record.is_file,
        size_bytes=record.size_bytes,
        modified_time_epoch=record.modified_time_epoch,
        sha256=record.sha256,
        error=record.error,
    )


def _index_baseline_entries(
    baseline: FileIntegrityBaseline,
) -> dict[str, FileIntegrityBaselineEntry]:
    entries_by_path: dict[str, FileIntegrityBaselineEntry] = {}

    for entry in baseline.entries:
        if entry.path in entries_by_path:
            raise ValueError(f"Duplicate path in file integrity baseline: {entry.path}")
        entries_by_path[entry.path] = entry

    return entries_by_path


def _compare_record_with_index(
    record: FileIntegrityRecord,
    entries_by_path: Mapping[str, FileIntegrityBaselineEntry],
) -> FileIntegrityBaselineComparison:
    current_entry = _entry_from_record(record)
    baseline_entry = entries_by_path.get(record.path)

    if baseline_entry is None:
        return FileIntegrityBaselineComparison(
            path=record.path,
            status=COMPARISON_NOT_IN_BASELINE,
            changed_fields=[],
            baseline_entry=None,
            current_entry=current_entry,
            message=f"File was not present in the baseline: {record.path}",
        )

    if record.error:
        return FileIntegrityBaselineComparison(
            path=record.path,
            status=COMPARISON_CURRENT_ERROR,
            changed_fields=["error"],
            baseline_entry=baseline_entry,
            current_entry=current_entry,
            message=f"File integrity check had an error for {record.path}",
        )

    if baseline_entry.exists and not record.exists:
        return FileIntegrityBaselineComparison(
            path=record.path,
            status=COMPARISON_MISSING_NOW,
            changed_fields=["exists"],
            baseline_entry=baseline_entry,
            current_entry=current_entry,
            message=f"File missing compared with baseline: {record.path}",
        )

    if not baseline_entry.exists and record.exists:
        return FileIntegrityBaselineComparison(
            path=record.path,
            status=COMPARISON_APPEARED_NOW,
            changed_fields=["exists"],
            baseline_entry=baseline_entry,
            current_entry=current_entry,
            message=f"File appeared compared with baseline: {record.path}",
        )

    if baseline_entry.is_file != record.is_file:
        return FileIntegrityBaselineComparison(
            path=record.path,
            status=COMPARISON_TYPE_CHANGED,
            changed_fields=["is_file"],
            baseline_entry=baseline_entry,
            current_entry=current_entry,
            message=f"File type changed compared with baseline: {record.path}",
        )

    changed_fields = []
    if baseline_entry.exists and record.exists and baseline_entry.is_file and record.is_file:
        changed_fields = [
            field_name
            for field_name in ("size_bytes", "modified_time_epoch", "sha256")
            if getattr(baseline_entry, field_name) != getattr(current_entry, field_name)
        ]
    if changed_fields:
        return FileIntegrityBaselineComparison(
            path=record.path,
            status=COMPARISON_CHANGED,
            changed_fields=changed_fields,
            baseline_entry=baseline_entry,
            current_entry=current_entry,
            message=f"File changed compared with baseline: {record.path}",
        )

    return FileIntegrityBaselineComparison(
        path=record.path,
        status=COMPARISON_UNCHANGED,
        changed_fields=[],
        baseline_entry=baseline_entry,
        current_entry=current_entry,
        message=f"File matches baseline: {record.path}",
    )


def compare_record_to_baseline(
    record: FileIntegrityRecord,
    baseline: FileIntegrityBaseline,
) -> FileIntegrityBaselineComparison:
    """Compare one existing observation with an unambiguous baseline."""
    return _compare_record_with_index(record, _index_baseline_entries(baseline))


def compare_records_to_baseline(
    records: Sequence[FileIntegrityRecord],
    baseline: FileIntegrityBaseline,
) -> list[FileIntegrityBaselineComparison]:
    """Compare observations with a baseline while preserving their input order."""
    entries_by_path = _index_baseline_entries(baseline)
    return [_compare_record_with_index(record, entries_by_path) for record in records]
