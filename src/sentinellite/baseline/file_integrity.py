from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinellite.collectors.file_integrity import FileIntegrityRecord

BASELINE_VERSION = 1


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
