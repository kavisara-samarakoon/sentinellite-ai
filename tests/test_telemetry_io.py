"""Filesystem hardening, writer-validation, failure-stage, and concurrency tests."""

from __future__ import annotations

import json
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sentinellite.reporting.telemetry import (
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    TELEMETRY_OUTPUT_TYPE,
    TelemetryError,
    TelemetryExport,
    TelemetryLimitExceededError,
    TelemetryOutputError,
    parse_telemetry_json,
    project_telemetry_from_bytes,
    serialize_telemetry_json,
)
from sentinellite.reporting.telemetry_io import (
    read_bounded_report_bytes,
    write_telemetry_file,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALID_REPORT = PROJECT_ROOT / "tests/fixtures/report_schema/schema_v1_alert.json"
FIXED_EXPORT_ID = "12345678-1234-4123-8123-123456789abc"
FIXED_EXPORTED_AT = "2026-11-27T12:00:00Z"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _private_source(src_dir: Path, name: str = "report.json", data: bytes | None = None) -> Path:
    target = src_dir / name
    target.write_bytes(VALID_REPORT.read_bytes() if data is None else data)
    os.chmod(target, 0o600)
    return target


def _valid_telemetry(
    *, export_id: str | None = None, exported_at: str | None = None
) -> TelemetryExport:
    return project_telemetry_from_bytes(
        VALID_REPORT.read_bytes(),
        _export_id=export_id,
        _exported_at=exported_at,
    )


def test_valid_private_directory_export_and_source_preservation(tmp_path: Path) -> None:
    priv = _private_dir(tmp_path / "private")
    src = _private_source(priv)
    before = src.read_bytes()
    out = priv / "telemetry.json"

    raw = read_bounded_report_bytes(src)
    telemetry = project_telemetry_from_bytes(
        raw, _export_id=FIXED_EXPORT_ID, _exported_at=FIXED_EXPORTED_AT
    )
    written = write_telemetry_file(out, telemetry)

    assert written == out
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert src.read_bytes() == before
    assert stat.S_IMODE(src.stat().st_mode) == 0o600
    parsed = parse_telemetry_json(out.read_bytes())
    assert parsed.export_id == FIXED_EXPORT_ID
    assert parsed.exported_at == FIXED_EXPORTED_AT
    assert parsed.alert_count >= 1


def test_f01_writer_rejects_invalid_payloads_before_filesystem_mutation(
    tmp_path: Path,
) -> None:
    priv = _private_dir(tmp_path / "priv")
    valid_bytes = serialize_telemetry_json(
        _valid_telemetry(export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT)
    )
    # Valid saved JSON bytes preserve export_id and exported_at.
    valid_out = priv / "from-bytes.json"
    write_telemetry_file(valid_out, valid_bytes)
    assert parse_telemetry_json(valid_out.read_bytes()).export_id == FIXED_EXPORT_ID

    notification_summary = json.dumps(
        {
            "schema_version": 1,
            "output_type": "sentinellite_notification_summary",
            "source": {"report_id": "r1", "generated_at": "2026-01-01T00:00:00Z"},
            "alert_count": 0,
            "included_alert_count": 0,
            "omitted_alert_count": 0,
            "severity_counts": {},
            "risk_level_counts": {},
            "alerts": [],
        }
    ).encode("utf-8")
    invalid_telemetry_values = json.dumps(
        {
            "schema_version": 2,
            "output_type": TELEMETRY_OUTPUT_TYPE,
            "export_id": FIXED_EXPORT_ID,
            "exported_at": FIXED_EXPORTED_AT,
            "alert_count": 0,
            "groups": [],
        }
    ).encode("utf-8")

    bad_payloads: list[object] = [
        b'{"unauthorized": true}',
        VALID_REPORT.read_bytes(),
        notification_summary,
        b"{malformed",
        b'{"schema_version": 1, "schema_version": 1}',
        b" " * (MAX_OUTPUT_BYTES + 1),
        invalid_telemetry_values,
        {"schema_version": 1, "output_type": "wrong"},
    ]

    for idx, bad in enumerate(bad_payloads):
        dest = priv / f"rejected-{idx}.json"
        with pytest.raises(TelemetryError):
            write_telemetry_file(dest, bad)  # type: ignore[arg-type]
        assert not dest.exists()
        assert not list(priv.glob("*.tmp"))


def test_insecure_permissions_and_wrong_ownership_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    telemetry = _valid_telemetry()
    # Insecure directory permissions (0755)
    pub_dir = tmp_path / "public_dir"
    pub_dir.mkdir()
    os.chmod(pub_dir, 0o755)
    src_in_pub = _private_source(pub_dir)
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(src_in_pub)
    with pytest.raises(TelemetryOutputError) as exc_out:
        write_telemetry_file(pub_dir / "out.json", telemetry)
    assert exc_out.value.published is False

    # Insecure source file permissions (0644) inside private 0700 dir
    priv = _private_dir(tmp_path / "priv")
    src_0644 = priv / "public_file.json"
    src_0644.write_bytes(VALID_REPORT.read_bytes())
    os.chmod(src_0644, 0o644)
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(src_0644)
    assert stat.S_IMODE(src_0644.stat().st_mode) == 0o644

    # Ownership mismatch via euid monkeypatch
    src_0600 = _private_source(priv)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1000)
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(src_0600)
    with pytest.raises(TelemetryOutputError):
        write_telemetry_file(priv / "owner_fail.json", telemetry)


def test_symlinks_directories_and_special_files_rejected(tmp_path: Path) -> None:
    telemetry = _valid_telemetry()
    priv = _private_dir(tmp_path / "priv")
    real_src = _private_source(priv, "real.json")

    # Source symlink
    src_link = priv / "link.json"
    src_link.symlink_to(real_src)
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(src_link)

    # Symlinked parent directory
    priv_link = tmp_path / "priv_link"
    priv_link.symlink_to(priv)
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(priv_link / "real.json")
    with pytest.raises(TelemetryOutputError):
        write_telemetry_file(priv_link / "out.json", telemetry)

    # Directory as source and output
    subdir = _private_dir(priv / "subdir")
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(subdir)
    with pytest.raises(TelemetryOutputError):
        write_telemetry_file(subdir, telemetry)

    # Dangling and live symlinks at output destination
    dangling = priv / "dangling.json"
    dangling.symlink_to(priv / "does_not_exist.json")
    with pytest.raises(TelemetryOutputError):
        write_telemetry_file(dangling, telemetry)

    live_link = priv / "live_link.json"
    live_link.symlink_to(real_src)
    before = real_src.read_bytes()
    with pytest.raises(TelemetryOutputError):
        write_telemetry_file(live_link, telemetry)
    assert real_src.read_bytes() == before


def test_fifo_rejected_without_hanging(tmp_path: Path) -> None:
    telemetry = _valid_telemetry()
    priv = _private_dir(tmp_path / "priv")
    fifo_path = priv / "input.fifo"
    os.mkfifo(fifo_path, 0o600)

    completed = threading.Event()
    errors: list[Exception] = []

    def _run() -> None:
        try:
            read_bounded_report_bytes(fifo_path)
        except Exception as err:  # noqa: BLE001
            errors.append(err)
        finally:
            completed.set()

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    assert completed.wait(timeout=2.0), "FIFO read hung instead of failing non-blocking."
    assert len(errors) == 1 and isinstance(errors[0], TelemetryOutputError)

    # Output destination FIFO also rejected
    with pytest.raises(TelemetryOutputError) as exc_out:
        write_telemetry_file(fifo_path, telemetry)
    assert exc_out.value.published is False


def test_missing_safety_primitives_and_unsupported_operations_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    telemetry = _valid_telemetry()
    priv = _private_dir(tmp_path / "priv")
    src = _private_source(priv)

    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(src)
    with pytest.raises(TelemetryOutputError):
        write_telemetry_file(priv / "out.json", telemetry)
    monkeypatch.undo()

    # F03: os.link raising NotImplementedError translates to sanitized TelemetryOutputError and cleans up temp
    def _unsupported_link(*_a: object, **_kw: object) -> None:
        raise NotImplementedError("link unsupported")

    monkeypatch.setattr(os, "link", _unsupported_link)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_unsupported_link})
    dest = priv / "unsupported-link.json"
    with pytest.raises(TelemetryOutputError, match="Failed publishing") as exc_link:
        write_telemetry_file(dest, telemetry)
    assert exc_link.value.published is False
    assert not dest.exists()
    assert not list(priv.glob("*.tmp"))
    monkeypatch.undo()

    # F03: os.open raising NotImplementedError on input translates cleanly
    def _unsupported_open(*_a: object, **_kw: object) -> int:
        raise NotImplementedError("openat unsupported")

    monkeypatch.setattr(os, "open", _unsupported_open)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_unsupported_open})
    with pytest.raises(TelemetryOutputError):
        read_bounded_report_bytes(src)


def test_oversized_max_bytes_bypass_and_concurrent_metadata_changes_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    priv = _private_dir(tmp_path / "priv")
    src = _private_source(priv, "valid.json")

    with pytest.raises(TelemetryLimitExceededError):
        read_bounded_report_bytes(src, _max_bytes=MAX_INPUT_BYTES + 1)

    oversized = _private_source(priv, "big.json", b"a" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(TelemetryLimitExceededError):
        read_bounded_report_bytes(oversized)

    # Simulate concurrent uid, mode, size, and ctime metadata changes between pre/post fstat
    real_fstat = os.fstat
    for field_index, delta in (
        (stat.ST_SIZE, 10),
        (stat.ST_UID, 1),
        (stat.ST_MODE, 0o044),
        (stat.ST_CTIME, 5),
    ):
        calls = {"count": 0}

        def _mutated_fstat(
            fd: int,
            *,
            _idx: int = field_index,
            _delta: int = delta,
            _calls: dict[str, int] = calls,
        ) -> os.stat_result:
            res = real_fstat(fd)
            _calls["count"] += 1
            if _calls["count"] == 3:
                values = list(res)
                values[_idx] = int(values[_idx]) + _delta
                return os.stat_result(values)
            return res

        monkeypatch.setattr(os, "fstat", _mutated_fstat)
        with pytest.raises(TelemetryOutputError, match="changed concurrently"):
            read_bounded_report_bytes(src)
        monkeypatch.undo()


def test_existing_destination_and_hard_link_protection(tmp_path: Path) -> None:
    telemetry = _valid_telemetry()
    priv = _private_dir(tmp_path / "priv")
    existing = _private_source(priv, "existing.json", b'{"keep": true}\n')
    hardlink = priv / "hardlink.json"
    os.link(existing, hardlink)

    for target in (existing, hardlink):
        with pytest.raises(TelemetryOutputError) as exc:
            write_telemetry_file(target, telemetry)
        assert exc.value.published is False

    assert existing.read_bytes() == b'{"keep": true}\n'
    assert hardlink.read_bytes() == b'{"keep": true}\n'


def test_write_short_chunks_and_injected_failure_stages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    priv = _private_dir(tmp_path / "priv")
    telemetry = _valid_telemetry(export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT)
    payload = serialize_telemetry_json(telemetry)

    # 1. Partial/short os.write handling succeeds cleanly
    real_write = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: real_write(fd, bytes(data)[:7]))
    short_out = priv / "short-write-ok.json"
    write_telemetry_file(short_out, telemetry)
    assert short_out.read_bytes() == payload
    monkeypatch.undo()

    # 2. Failure before temporary creation (existing dest leaves zero .tmp files)
    with pytest.raises(TelemetryOutputError) as exc_pre:
        write_telemetry_file(short_out, telemetry)
    assert exc_pre.value.published is False
    assert not list(priv.glob("*.tmp"))

    # 3. Write failure + cleanup success
    out_write_fail = priv / "write-fail.json"
    monkeypatch.setattr(os, "write", lambda _fd, _data: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(TelemetryOutputError, match="Failed writing") as exc_w:
        write_telemetry_file(out_write_fail, telemetry)
    assert exc_w.value.published is False
    assert not out_write_fail.exists()
    assert not list(priv.glob("*.tmp"))
    monkeypatch.undo()

    # 4. File fsync failure + cleanup success
    out_fsync_fail = priv / "fsync-fail.json"
    monkeypatch.setattr(os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("io err")))
    with pytest.raises(TelemetryOutputError, match="Failed synchronizing") as exc_fs:
        write_telemetry_file(out_fsync_fail, telemetry)
    assert exc_fs.value.published is False
    assert not out_fsync_fail.exists()
    assert not list(priv.glob("*.tmp"))
    monkeypatch.undo()

    # 5. Publication (os.link) failure + cleanup success
    out_link_fail = priv / "link-fail.json"

    def _fail_link(*_a: object, **_kw: object) -> None:
        raise FileExistsError()

    monkeypatch.setattr(os, "link", _fail_link)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_fail_link})
    with pytest.raises(TelemetryOutputError, match="overwrite refused") as exc_link:
        write_telemetry_file(out_link_fail, telemetry)
    assert exc_link.value.published is False
    assert not out_link_fail.exists()
    assert not list(priv.glob("*.tmp"))
    monkeypatch.undo()

    # 6. F02 combined pre-publication cleanup failures (write/cleanup, fsync/cleanup, link/cleanup)
    def _fail_unlink(*_a: object, **_kw: object) -> None:
        raise OSError("unlink denied")

    for stage_name, patch_fn in (
        (
            "write",
            lambda: monkeypatch.setattr(
                os, "write", lambda _fd, _d: (_ for _ in ()).throw(OSError("disk full"))
            ),
        ),
        (
            "fsync",
            lambda: monkeypatch.setattr(
                os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("io err"))
            ),
        ),
        (
            "link",
            lambda: (
                monkeypatch.setattr(os, "link", _fail_link),
                monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_fail_link}),
            ),
        ),
    ):
        patch_fn()
        monkeypatch.setattr(os, "unlink", _fail_unlink)
        monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_fail_unlink})
        combo_dest = priv / f"combo-{stage_name}.json"
        with pytest.raises(
            TelemetryOutputError, match="private temporary file may remain"
        ) as exc_combo:
            write_telemetry_file(combo_dest, telemetry)
        assert exc_combo.value.published is False
        assert not combo_dest.exists()
        monkeypatch.undo()
        for left_tmp in priv.glob("*.tmp"):
            left_tmp.unlink()

    # 7. Post-publication temporary cleanup failure reports published=True and preserves output
    out_unlink_fail = priv / "unlink-fail.json"
    monkeypatch.setattr(os, "unlink", _fail_unlink)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_fail_unlink})
    with pytest.raises(TelemetryOutputError, match="cleanup failed") as exc_un:
        write_telemetry_file(out_unlink_fail, telemetry)
    assert exc_un.value.published is True
    assert out_unlink_fail.read_bytes() == payload
    monkeypatch.undo()
    for left_tmp in priv.glob("*.tmp"):
        left_tmp.unlink()

    # 8. Post-publication directory fsync failure reports published=True and preserves output
    out_dirsync_fail = priv / "dirsync-fail.json"
    real_fsync = os.fsync
    fsync_calls = {"n": 0}

    def _fail_second_fsync(fd: int) -> None:
        fsync_calls["n"] += 1
        if fsync_calls["n"] == 2:
            raise OSError("dir fsync unsupported")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _fail_second_fsync)
    with pytest.raises(TelemetryOutputError, match="durability sync failed") as exc_ds:
        write_telemetry_file(out_dirsync_fail, telemetry)
    assert exc_ds.value.published is True
    assert out_dirsync_fail.read_bytes() == payload


def test_concurrent_exporters_single_winner_no_overwrite(tmp_path: Path) -> None:
    priv = _private_dir(tmp_path / "priv")
    dest = priv / "winner.json"
    t1 = _valid_telemetry()
    t2 = _valid_telemetry()
    p1 = serialize_telemetry_json(t1)
    p2 = serialize_telemetry_json(t2)
    barrier = threading.Barrier(2)

    def _publish(telemetry: TelemetryExport) -> str:
        barrier.wait(timeout=5.0)
        try:
            write_telemetry_file(dest, telemetry)
        except TelemetryError as err:
            return f"err:{err.outcome.value}"
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_publish, t1)
        f2 = pool.submit(_publish, t2)
        outcomes = sorted([f1.result(), f2.result()])

    assert outcomes == ["err:output-error", "ok"]
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert dest.read_bytes() in (p1, p2)
    assert parse_telemetry_json(dest.read_bytes()).alert_count >= 1
    assert not list(priv.glob("*.tmp"))
