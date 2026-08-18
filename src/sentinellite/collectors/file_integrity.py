from __future__ import annotations

import hashlib
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

HASH_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True, slots=True)
class FileIntegrityRecord:
    """Read-only metadata and hash information for a selected path."""

    path: str
    exists: bool
    is_file: bool
    size_bytes: int | None
    modified_time_epoch: float | None
    sha256: str | None
    error: str | None


def calculate_sha256(path: Path) -> str:
    """Calculate a SHA-256 digest by reading a file in fixed-size chunks."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(HASH_CHUNK_SIZE):
            digest.update(chunk)

    return digest.hexdigest()


def collect_file_integrity(paths: Sequence[Path | str]) -> list[FileIntegrityRecord]:
    """Collect metadata and hashes for explicitly selected paths without modifying them."""
    records: list[FileIntegrityRecord] = []

    for supplied_path in paths:
        path = Path(supplied_path)

        try:
            path_stat = path.stat()
        except FileNotFoundError:
            records.append(
                FileIntegrityRecord(
                    path=str(path),
                    exists=False,
                    is_file=False,
                    size_bytes=None,
                    modified_time_epoch=None,
                    sha256=None,
                    error=f"Path does not exist: {path}",
                )
            )
            continue
        except OSError as error:
            records.append(
                FileIntegrityRecord(
                    path=str(path),
                    exists=False,
                    is_file=False,
                    size_bytes=None,
                    modified_time_epoch=None,
                    sha256=None,
                    error=f"Unable to inspect path: {error}",
                )
            )
            continue

        is_file = stat.S_ISREG(path_stat.st_mode)
        if not is_file:
            records.append(
                FileIntegrityRecord(
                    path=str(path),
                    exists=True,
                    is_file=False,
                    size_bytes=None,
                    modified_time_epoch=None,
                    sha256=None,
                    error=None,
                )
            )
            continue

        try:
            file_hash = calculate_sha256(path)
        except OSError as error:
            records.append(
                FileIntegrityRecord(
                    path=str(path),
                    exists=True,
                    is_file=True,
                    size_bytes=path_stat.st_size,
                    modified_time_epoch=path_stat.st_mtime,
                    sha256=None,
                    error=f"Unable to read file: {error}",
                )
            )
            continue

        records.append(
            FileIntegrityRecord(
                path=str(path),
                exists=True,
                is_file=True,
                size_bytes=path_stat.st_size,
                modified_time_epoch=path_stat.st_mtime,
                sha256=file_hash,
                error=None,
            )
        )

    return records
