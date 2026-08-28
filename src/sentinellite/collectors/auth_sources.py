import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class AuthLogSourceError(Exception):
    """Base error for expected authentication log source failures."""


class AuthLogNotFoundError(AuthLogSourceError, FileNotFoundError):
    """Raised when a selected authentication log path does not exist."""


class AuthLogUnreadableError(AuthLogSourceError):
    """Raised when an authentication log cannot be inspected or read."""


class UnsupportedAuthLogSourceError(AuthLogSourceError):
    """Raised when an authentication log path is not a regular file."""


class MalformedAuthLogError(AuthLogSourceError):
    """Raised when an authentication log is not valid UTF-8 text."""


@dataclass(frozen=True, slots=True)
class AuthLogCandidate:
    family: str
    path: Path


@dataclass(frozen=True, slots=True)
class AuthLogSourceEntry:
    family: str
    path: Path
    status: str
    error: str | None


DEFAULT_AUTH_LOG_CANDIDATES: tuple[AuthLogCandidate, ...] = (
    AuthLogCandidate(family="debian_ubuntu", path=Path("/var/log/auth.log")),
    AuthLogCandidate(family="rhel_fedora", path=Path("/var/log/secure")),
)


def inspect_auth_log_source(candidate: AuthLogCandidate) -> AuthLogSourceEntry:
    """Inspect one candidate without reading or modifying its contents."""
    path = candidate.path
    try:
        path_stat = path.stat()
    except FileNotFoundError:
        return _entry(candidate, "missing", f"Authentication log file not found: {path}")
    except OSError as error:
        return _entry(
            candidate,
            "unreadable",
            f"Unable to inspect authentication log '{path}': {error}",
        )

    if not stat.S_ISREG(path_stat.st_mode):
        return _entry(
            candidate,
            "unsupported",
            f"Authentication log path is not a regular file: {path}",
        )

    try:
        with path.open("rb") as source_file:
            if not stat.S_ISREG(os.fstat(source_file.fileno()).st_mode):
                return _entry(
                    candidate,
                    "unsupported",
                    f"Authentication log path is not a regular file: {path}",
                )
    except FileNotFoundError:
        return _entry(candidate, "missing", f"Authentication log file not found: {path}")
    except IsADirectoryError:
        return _entry(
            candidate,
            "unsupported",
            f"Authentication log path is not a regular file: {path}",
        )
    except OSError as error:
        return _entry(
            candidate,
            "unreadable",
            f"Unable to open authentication log '{path}': {error}",
        )

    return _entry(candidate, "available", None)


def discover_auth_log_sources(
    candidates: Sequence[AuthLogCandidate] = DEFAULT_AUTH_LOG_CANDIDATES,
) -> tuple[AuthLogSourceEntry, ...]:
    """Inspect authentication log candidates independently in supplied order."""
    return tuple(inspect_auth_log_source(candidate) for candidate in candidates)


def validate_auth_log_path(path: Path) -> Path:
    """Validate that a selected path is a readable regular UTF-8 text file."""
    try:
        path_stat = path.stat()
    except FileNotFoundError as error:
        raise AuthLogNotFoundError(
            f"Authentication log file not found: {path}"
        ) from error
    except OSError as error:
        raise AuthLogUnreadableError(
            f"Unable to inspect authentication log '{path}': {error}"
        ) from error

    if not stat.S_ISREG(path_stat.st_mode):
        raise UnsupportedAuthLogSourceError(
            f"Authentication log path is not a regular file: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as source_file:
            if not stat.S_ISREG(os.fstat(source_file.fileno()).st_mode):
                raise UnsupportedAuthLogSourceError(
                    f"Authentication log path is not a regular file: {path}"
                )
            source_file.read(4096)
    except AuthLogSourceError:
        raise
    except FileNotFoundError as error:
        raise AuthLogNotFoundError(
            f"Authentication log file not found: {path}"
        ) from error
    except IsADirectoryError as error:
        raise UnsupportedAuthLogSourceError(
            f"Authentication log path is not a regular file: {path}"
        ) from error
    except UnicodeDecodeError as error:
        raise MalformedAuthLogError(
            f"Authentication log is not valid UTF-8: {path}"
        ) from error
    except OSError as error:
        raise AuthLogUnreadableError(
            f"Unable to open authentication log '{path}': {error}"
        ) from error

    return path


def _entry(
    candidate: AuthLogCandidate,
    status: str,
    error: str | None,
) -> AuthLogSourceEntry:
    return AuthLogSourceEntry(
        family=candidate.family,
        path=candidate.path,
        status=status,
        error=error,
    )
