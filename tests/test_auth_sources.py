import os
from pathlib import Path

import pytest

from sentinellite.collectors.auth_sources import (
    DEFAULT_AUTH_LOG_CANDIDATES,
    AuthLogCandidate,
    AuthLogSourceEntry,
    AuthLogUnreadableError,
    MalformedAuthLogError,
    UnsupportedAuthLogSourceError,
    discover_auth_log_sources,
    inspect_auth_log_source,
    validate_auth_log_path,
)


def test_default_auth_log_candidates_have_expected_order_and_labels() -> None:
    assert DEFAULT_AUTH_LOG_CANDIDATES == (
        AuthLogCandidate("debian_ubuntu", Path("/var/log/auth.log")),
        AuthLogCandidate("rhel_fedora", Path("/var/log/secure")),
    )


def test_discover_auth_log_sources_preserves_candidate_order(tmp_path: Path) -> None:
    candidates = (
        AuthLogCandidate("second", tmp_path / "second.log"),
        AuthLogCandidate("first", tmp_path / "first.log"),
    )

    entries = discover_auth_log_sources(candidates)

    assert [entry.family for entry in entries] == ["second", "first"]
    assert [entry.path for entry in entries] == [
        tmp_path / "second.log",
        tmp_path / "first.log",
    ]


def test_regular_readable_candidate_is_available(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("authentication event\n", encoding="utf-8")

    entry = inspect_auth_log_source(AuthLogCandidate("test", log_path))

    assert entry == AuthLogSourceEntry("test", log_path, "available", None)
    assert validate_auth_log_path(log_path) == log_path


def test_missing_candidate_is_reported_without_raising(tmp_path: Path) -> None:
    log_path = tmp_path / "missing.log"

    entry = inspect_auth_log_source(AuthLogCandidate("test", log_path))

    assert entry.status == "missing"
    assert entry.path == log_path
    assert entry.error is not None
    assert str(log_path) in entry.error


def test_directory_candidate_is_unsupported(tmp_path: Path) -> None:
    entry = inspect_auth_log_source(AuthLogCandidate("test", tmp_path))

    assert entry.status == "unsupported"
    assert entry.error is not None
    with pytest.raises(UnsupportedAuthLogSourceError, match="not a regular file"):
        validate_auth_log_path(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_fifo_candidate_is_unsupported_without_opening_it(tmp_path: Path) -> None:
    fifo_path = tmp_path / "auth.fifo"
    os.mkfifo(fifo_path)

    entry = inspect_auth_log_source(AuthLogCandidate("test", fifo_path))

    assert entry.status == "unsupported"
    with pytest.raises(UnsupportedAuthLogSourceError, match="not a regular file"):
        validate_auth_log_path(fifo_path)


def test_symlink_to_regular_file_is_available(tmp_path: Path) -> None:
    target = tmp_path / "auth-target.log"
    target.write_text("authentication event\n", encoding="utf-8")
    link = tmp_path / "auth.log"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symlinks are unavailable: {error}")

    entry = inspect_auth_log_source(AuthLogCandidate("test", link))

    assert entry.status == "available"
    assert validate_auth_log_path(link) == link


def test_symlink_to_directory_is_unsupported(tmp_path: Path) -> None:
    target = tmp_path / "logs"
    target.mkdir()
    link = tmp_path / "auth.log"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlinks are unavailable: {error}")

    entry = inspect_auth_log_source(AuthLogCandidate("test", link))

    assert entry.status == "unsupported"
    with pytest.raises(UnsupportedAuthLogSourceError, match="not a regular file"):
        validate_auth_log_path(link)


def test_unreadable_candidate_uses_clean_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("private authentication event\n", encoding="utf-8")
    original_open = Path.open

    def deny_selected_path(path: Path, *args: object, **kwargs: object):
        if path == log_path:
            raise PermissionError("simulated permission denial")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_selected_path)

    entry = inspect_auth_log_source(AuthLogCandidate("test", log_path))

    assert entry.status == "unreadable"
    assert entry.error is not None
    assert str(log_path) in entry.error
    with pytest.raises(AuthLogUnreadableError, match="simulated permission denial"):
        validate_auth_log_path(log_path)


def test_missing_candidate_does_not_hide_available_candidate(tmp_path: Path) -> None:
    available_path = tmp_path / "secure"
    available_path.write_text("authentication event\n", encoding="utf-8")
    candidates = (
        AuthLogCandidate("missing", tmp_path / "auth.log"),
        AuthLogCandidate("available", available_path),
    )

    entries = discover_auth_log_sources(candidates)

    assert [entry.status for entry in entries] == ["missing", "available"]


def test_candidate_injection_uses_only_supplied_paths(tmp_path: Path) -> None:
    supplied_path = tmp_path / "custom-auth.log"
    supplied_path.write_text("authentication event\n", encoding="utf-8")

    entries = discover_auth_log_sources(
        (AuthLogCandidate("injected", supplied_path),)
    )

    assert entries == (
        AuthLogSourceEntry("injected", supplied_path, "available", None),
    )


def test_inspection_and_validation_do_not_change_file_contents(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    original = b"first authentication event\nsecond authentication event\n"
    log_path.write_bytes(original)

    inspect_auth_log_source(AuthLogCandidate("test", log_path))
    validate_auth_log_path(log_path)

    assert log_path.read_bytes() == original


def test_validate_auth_log_path_rejects_invalid_utf8(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_bytes(b"valid prefix\n\xff\xfe")

    with pytest.raises(MalformedAuthLogError, match="not valid UTF-8"):
        validate_auth_log_path(log_path)
