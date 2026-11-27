"""Hardened local filesystem acquisition and private atomic no-clobber publication.

Security model and residual limitations:
- Parent directories for both source input and telemetry output must already exist,
  be owned by the effective user (``os.geteuid()``), have strict mode ``0o700``,
  and not be symbolic links at the final directory component (``O_NOFOLLOW``).
- Source files must be owned by the effective user with no group/other permission
  bits (``mode & 0o077 == 0``, e.g. ``0o600``) and must be regular files opened
  with ``O_RDONLY | O_NONBLOCK | O_NOFOLLOW`` via the pinned directory descriptor.
- POSIX mode checks assume trusted ancestor directories, trusted ACL
  configurations, and trusted filesystems; they do not universally prove absence
  of alternative access grants (for example, POSIX ACLs) or protect against
  arbitrary equivalent-privilege processes.
- ``O_NOFOLLOW`` protects the pinned final directory and file components, not
  arbitrary ancestor path components.
- Post-read ``fstat`` metadata checks (device, inode, ownership, mode, size,
  mtime, and ctime) detect concurrent changes on the open descriptor, but do not
  guarantee an immutable snapshot against another equivalent-privilege process.
- ``write_telemetry_file()`` strictly validates and canonically serializes the
  supplied telemetry payload before any filesystem mutation.
- Output publication creates a private ``0o600`` temporary file in the pinned
  destination directory, writes all bytes, calls ``os.fsync()`` on the file, and
  publishes via atomic no-clobber ``os.link(..., src_dir_fd=..., dst_dir_fd=...)``
  before unlinking the temporary name and calling ``os.fsync()`` on the directory.
- Pre-publication failures unlink the temporary file and preserve
  ``published=False``; if temporary cleanup also fails, the sanitized error
  explicitly reports possible private temporary-file residue without losing the
  original operation failure. Post-publication cleanup or directory-fsync failures
  report ``published=True`` and never delete the published final destination.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sentinellite.reporting.telemetry import (
    MAX_INPUT_BYTES,
    TelemetryExport,
    TelemetryIncompatibleError,
    TelemetryLimitExceededError,
    TelemetryOutputError,
    parse_telemetry_json,
    serialize_telemetry_json,
)

_READ_CHUNK_SIZE = 64 * 1024


def _require_safety_primitives() -> None:
    required = (
        hasattr(os, "O_NOFOLLOW"),
        hasattr(os, "O_NONBLOCK"),
        hasattr(os, "O_DIRECTORY"),
        hasattr(os, "geteuid"),
        hasattr(os, "fstat"),
        hasattr(os, "fsync"),
        hasattr(os, "fchmod"),
        hasattr(os, "read"),
        hasattr(os, "write"),
        hasattr(os, "close"),
        os.open in os.supports_dir_fd,
        os.link in os.supports_dir_fd,
        os.unlink in os.supports_dir_fd,
        os.stat in os.supports_dir_fd,
        os.stat in os.supports_follow_symlinks,
    )
    if not all(required):
        raise TelemetryOutputError(
            "Required filesystem safety primitives are unsupported on this platform.",
            published=False,
        )


def _validate_leaf_name(path: Path, *, role: str) -> str:
    name = path.name
    if not name or name in (".", ".."):
        raise TelemetryOutputError(
            f"Telemetry {role} path must reference a valid filename.",
            published=False,
        )
    return name


def _open_trusted_directory(directory: Path, *, role: str) -> int:
    _require_safety_primitives()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        dir_fd = os.open(directory, flags)
    except (OSError, NotImplementedError):
        raise TelemetryOutputError(
            f"Telemetry {role} parent directory could not be opened safely.",
            published=False,
        ) from None

    try:
        dir_stat = os.fstat(dir_fd)
        if not stat.S_ISDIR(dir_stat.st_mode):
            raise TelemetryOutputError(
                f"Telemetry {role} parent path is not a directory.",
                published=False,
            )
        if dir_stat.st_uid != os.geteuid():
            raise TelemetryOutputError(
                f"Telemetry {role} parent directory is not owned by the current user.",
                published=False,
            )
        if stat.S_IMODE(dir_stat.st_mode) != 0o700:
            raise TelemetryOutputError(
                f"Telemetry {role} parent directory must have private mode 0700.",
                published=False,
            )
    except TelemetryOutputError:
        _close_fd_safely(dir_fd)
        raise
    except (OSError, NotImplementedError):
        _close_fd_safely(dir_fd)
        raise TelemetryOutputError(
            f"Telemetry {role} parent directory failed metadata verification.",
            published=False,
        ) from None

    return dir_fd


def _close_fd_safely(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except (OSError, NotImplementedError):
        pass


def _source_metadata_tuple(file_stat: os.stat_result) -> tuple[object, ...]:
    ctime_ns = getattr(file_stat, "st_ctime_ns", int(file_stat.st_ctime * 1_000_000_000))
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_uid,
        stat.S_IMODE(file_stat.st_mode),
        file_stat.st_size,
        file_stat.st_mtime_ns,
        ctime_ns,
    )


def read_bounded_report_bytes(
    report_path: Path,
    *,
    _max_bytes: int = MAX_INPUT_BYTES,
) -> bytes:
    """Safely read one private regular report file up to ``MAX_INPUT_BYTES``."""
    if type(_max_bytes) is not int or _max_bytes < 0 or _max_bytes > MAX_INPUT_BYTES:
        raise TelemetryLimitExceededError(
            f"Configured input read bound cannot exceed {MAX_INPUT_BYTES} bytes."
        )

    filename = _validate_leaf_name(report_path, role="source")
    dir_fd = _open_trusted_directory(report_path.parent, role="source")
    file_fd: int | None = None

    try:
        open_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        try:
            file_fd = os.open(filename, open_flags, dir_fd=dir_fd)
        except (OSError, NotImplementedError):
            raise TelemetryOutputError(
                "Source report could not be opened safely.",
                published=False,
            ) from None

        try:
            before_stat = os.fstat(file_fd)
        except (OSError, NotImplementedError):
            raise TelemetryOutputError(
                "Source report metadata could not be verified.",
                published=False,
            ) from None

        if not stat.S_ISREG(before_stat.st_mode):
            raise TelemetryOutputError(
                "Source report path must be a regular file.",
                published=False,
            )
        if before_stat.st_uid != os.geteuid():
            raise TelemetryOutputError(
                "Source report is not owned by the current user.",
                published=False,
            )
        if stat.S_IMODE(before_stat.st_mode) & 0o077 != 0:
            raise TelemetryOutputError(
                "Source report must have private owner-only permissions (no group/other bits).",
                published=False,
            )
        if before_stat.st_size > _max_bytes:
            raise TelemetryLimitExceededError(f"Source report exceeds {_max_bytes}-byte limit.")

        chunks: list[bytes] = []
        total_read = 0
        limit = _max_bytes + 1
        while total_read < limit:
            to_read = min(_READ_CHUNK_SIZE, limit - total_read)
            try:
                chunk = os.read(file_fd, to_read)
            except (OSError, NotImplementedError):
                raise TelemetryOutputError(
                    "Failed reading source report bytes.",
                    published=False,
                ) from None
            if not chunk:
                break
            chunks.append(chunk)
            total_read += len(chunk)

        if total_read > _max_bytes:
            raise TelemetryLimitExceededError(f"Source report exceeds {_max_bytes}-byte limit.")

        try:
            after_stat = os.fstat(file_fd)
        except (OSError, NotImplementedError):
            raise TelemetryOutputError(
                "Source report metadata could not be re-verified after reading.",
                published=False,
            ) from None

        if (
            _source_metadata_tuple(before_stat) != _source_metadata_tuple(after_stat)
            or total_read != after_stat.st_size
        ):
            raise TelemetryOutputError(
                "Source report changed concurrently during read.",
                published=False,
            )

        return b"".join(chunks)
    finally:
        _close_fd_safely(file_fd)
        _close_fd_safely(dir_fd)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    total = len(payload)
    while offset < total:
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("Short or zero write while writing telemetry output.")
        offset += written


def _pre_publication_error(
    temp_name: str,
    *,
    dir_fd: int,
    message: str,
) -> TelemetryOutputError:
    """Clean up an unpublished temporary file and report cleanup failures explicitly."""
    try:
        os.unlink(temp_name, dir_fd=dir_fd)
    except (OSError, NotImplementedError):
        return TelemetryOutputError(
            f"{message} Temporary cleanup also failed; a private temporary file may remain in the output directory.",
            published=False,
        )
    return TelemetryOutputError(message, published=False)


def _validate_and_serialize_for_write(
    payload: TelemetryExport | Mapping[str, Any] | bytes | bytearray | str,
    *,
    _max_output_bytes: int | None = None,
) -> bytes:
    if isinstance(payload, (bytes, bytearray, str)):
        parsed = parse_telemetry_json(payload)
        if _max_output_bytes is None:
            return serialize_telemetry_json(parsed)
        return serialize_telemetry_json(parsed, _max_output_bytes=_max_output_bytes)
    if isinstance(payload, (TelemetryExport, Mapping)):
        if _max_output_bytes is None:
            return serialize_telemetry_json(payload)
        return serialize_telemetry_json(payload, _max_output_bytes=_max_output_bytes)
    raise TelemetryIncompatibleError(
        "Telemetry output payload must be a TelemetryExport, mapping, or UTF-8 JSON."
    )


def write_telemetry_file(
    output_path: Path,
    payload: TelemetryExport | Mapping[str, Any] | bytes | bytearray | str,
    *,
    _max_output_bytes: int | None = None,
) -> Path:
    """Validate, canonically serialize, and publish telemetry atomically without clobber."""
    payload_bytes = _validate_and_serialize_for_write(
        payload,
        _max_output_bytes=_max_output_bytes,
    )

    filename = _validate_leaf_name(output_path, role="output")
    dir_fd = _open_trusted_directory(output_path.parent, role="output")
    temp_fd: int | None = None
    temp_name: str | None = None

    try:
        # Reject pre-existing destination before creating any temporary file.
        try:
            os.stat(filename, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except (OSError, NotImplementedError):
            raise TelemetryOutputError(
                "Telemetry destination path could not be inspected safely.",
                published=False,
            ) from None
        else:
            raise TelemetryOutputError(
                "Telemetry destination already exists; overwrite refused.",
                published=False,
            )

        temp_name = f".sentinellite-telemetry-{os.getpid()}-{secrets.token_hex(8)}.tmp"
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            temp_fd = os.open(temp_name, create_flags, 0o600, dir_fd=dir_fd)
        except (OSError, NotImplementedError):
            temp_name = None
            raise TelemetryOutputError(
                "Could not create private telemetry temporary file.",
                published=False,
            ) from None

        try:
            temp_stat = os.fstat(temp_fd)
            if not stat.S_ISREG(temp_stat.st_mode) or temp_stat.st_uid != os.geteuid():
                raise TelemetryOutputError(
                    "Telemetry temporary file failed ownership or type verification.",
                    published=False,
                )
            if stat.S_IMODE(temp_stat.st_mode) != 0o600:
                os.fchmod(temp_fd, 0o600)
        except TelemetryOutputError as err:
            _close_fd_safely(temp_fd)
            temp_fd = None
            raise _pre_publication_error(temp_name, dir_fd=dir_fd, message=str(err)) from None
        except (OSError, NotImplementedError):
            _close_fd_safely(temp_fd)
            temp_fd = None
            raise _pre_publication_error(
                temp_name,
                dir_fd=dir_fd,
                message="Telemetry temporary file permission verification failed; no final output was published.",
            ) from None

        try:
            _write_all(temp_fd, payload_bytes)
        except (OSError, NotImplementedError):
            _close_fd_safely(temp_fd)
            temp_fd = None
            raise _pre_publication_error(
                temp_name,
                dir_fd=dir_fd,
                message="Failed writing telemetry temporary file; no final output was published.",
            ) from None

        try:
            os.fsync(temp_fd)
        except (OSError, NotImplementedError):
            _close_fd_safely(temp_fd)
            temp_fd = None
            raise _pre_publication_error(
                temp_name,
                dir_fd=dir_fd,
                message="Failed synchronizing telemetry temporary file; no final output was published.",
            ) from None

        try:
            os.close(temp_fd)
        except (OSError, NotImplementedError):
            temp_fd = None
            raise _pre_publication_error(
                temp_name,
                dir_fd=dir_fd,
                message="Failed closing telemetry temporary file; no final output was published.",
            ) from None
        temp_fd = None

        try:
            os.link(temp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except FileExistsError:
            raise _pre_publication_error(
                temp_name,
                dir_fd=dir_fd,
                message="Telemetry destination already exists; overwrite refused.",
            ) from None
        except (OSError, NotImplementedError):
            raise _pre_publication_error(
                temp_name,
                dir_fd=dir_fd,
                message="Failed publishing telemetry file; no final output was published.",
            ) from None

        try:
            os.unlink(temp_name, dir_fd=dir_fd)
        except (OSError, NotImplementedError):
            raise TelemetryOutputError(
                "Telemetry output was published, but temporary-file cleanup failed.",
                published=True,
            ) from None

        try:
            os.fsync(dir_fd)
        except (OSError, NotImplementedError):
            raise TelemetryOutputError(
                "Telemetry output was published, but directory durability sync failed.",
                published=True,
            ) from None

        return output_path
    finally:
        _close_fd_safely(temp_fd)
        _close_fd_safely(dir_fd)
