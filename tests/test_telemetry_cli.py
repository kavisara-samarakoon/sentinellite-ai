"""CLI, confidentiality, regression, network-guard, and entry-point tests for export-telemetry."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import sysconfig
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinellite.main import app
from sentinellite.reporting.telemetry import (
    TELEMETRY_OUTPUT_TYPE,
    TELEMETRY_TOP_LEVEL_KEYS,
    parse_telemetry_json,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALID_REPORT = PROJECT_ROOT / "tests/fixtures/report_schema/schema_v1_alert.json"
LEGACY_REPORT = PROJECT_ROOT / "tests/fixtures/report_schema/legacy_unversioned_alert.json"
CONSOLE_SCRIPT = Path(sysconfig.get_path("scripts")) / "sentinellite"

runner = CliRunner()


def _setup_private_source(tmp_path: Path, src_bytes: bytes | None = None) -> tuple[Path, Path]:
    priv = tmp_path / "private"
    priv.mkdir()
    os.chmod(priv, 0o700)
    src = priv / "source.json"
    src.write_bytes(VALID_REPORT.read_bytes() if src_bytes is None else src_bytes)
    os.chmod(src, 0o600)
    return priv, src


def test_cli_export_telemetry_succeeds_and_preserves_source(tmp_path: Path) -> None:
    priv, src = _setup_private_source(tmp_path)
    before = src.read_bytes()
    out = priv / "telemetry.json"

    result = runner.invoke(
        app,
        ["reports", "export-telemetry", str(src), "--output", str(out)],
    )

    assert result.exit_code == 0, result.output
    assert "Offline telemetry exported successfully." in result.output
    assert str(src) not in result.output
    assert src.read_bytes() == before
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    parsed = parse_telemetry_json(out.read_bytes())
    assert parsed.schema_version == 1
    assert parsed.output_type == TELEMETRY_OUTPUT_TYPE
    assert set(parsed.to_dict()) == TELEMETRY_TOP_LEVEL_KEYS


def test_cli_missing_output_argument_and_invalid_paths_fail_cleanly(tmp_path: Path) -> None:
    priv, src = _setup_private_source(tmp_path)

    missing_opt = runner.invoke(app, ["reports", "export-telemetry", str(src)])
    assert missing_opt.exit_code != 0

    same_path = runner.invoke(app, ["reports", "export-telemetry", str(src), "--output", str(src)])
    assert same_path.exit_code != 0
    assert "Traceback" not in same_path.output

    # Insecure directory permissions fail cleanly without echoing sensitive source path
    pub = tmp_path / "public"
    pub.mkdir()
    os.chmod(pub, 0o755)
    bad_src = pub / "secret-path-name.json"
    bad_src.write_bytes(VALID_REPORT.read_bytes())
    os.chmod(bad_src, 0o600)
    bad_res = runner.invoke(
        app,
        ["reports", "export-telemetry", str(bad_src), "--output", str(priv / "o.json")],
    )
    assert bad_res.exit_code != 0
    assert "secret-path-name.json" not in bad_res.output
    assert "Traceback" not in bad_res.output


def test_cli_c01_nested_evidence_confidentiality_and_sanitized_output(
    tmp_path: Path,
) -> None:
    canary = "CLI_CANARY_EVIDENCE_KEY_XYZ123"
    report = {
        "schema_version": 1,
        "report_id": "report-cli-c01",
        "report_type": "sentinellite_alert_report",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "alert_count": 1,
        "alerts": [
            {
                "alert_id": "a1",
                "rule_id": "AUTH-001",
                "rule_name": "Failed SSH",
                "category": "authentication",
                "severity": "medium",
                "base_score": 50,
                "risk_score": 50,
                "risk_level": "medium",
                "event_id": "e1",
                "event_type": "ssh_failed_login",
                "source": "sshd",
                "message": "msg",
                "description": "desc",
                "recommendation": "rec",
                "evidence": {canary: {"bad": "\ud800"}},
            }
        ],
    }
    priv, src = _setup_private_source(tmp_path, json.dumps(report).encode("utf-8"))
    out = priv / "telemetry.json"

    result = runner.invoke(
        app,
        ["reports", "export-telemetry", str(src), "--output", str(out)],
    )

    assert result.exit_code != 0
    assert canary not in result.output
    assert str(src) not in result.output
    assert "Traceback" not in result.output
    assert not out.exists()


def test_existing_commands_do_not_create_telemetry_artifacts(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    demo_res = runner.invoke(app, ["demo", "--output-dir", str(report_dir)])
    assert demo_res.exit_code == 0, demo_res.output
    reports = list(report_dir.glob("*.json"))
    assert len(reports) == 1

    notif_path = tmp_path / "notif.json"
    notif_res = runner.invoke(
        app, ["reports", "export-notification", str(reports[0]), "--output", str(notif_path)]
    )
    assert notif_res.exit_code == 0, notif_res.output
    assert "sentinellite_telemetry" not in reports[0].read_text(encoding="utf-8")
    assert "sentinellite_telemetry" not in notif_path.read_text(encoding="utf-8")


def test_cli_export_telemetry_performs_no_network_or_credential_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _forbid(*args: object, **kwargs: object) -> None:
        raise AssertionError("Network access is forbidden during offline telemetry export.")

    monkeypatch.setattr(socket, "socket", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)
    monkeypatch.setattr(urllib.request, "urlopen", _forbid)

    priv, src = _setup_private_source(tmp_path)
    out = priv / "telemetry.json"
    result = runner.invoke(app, ["reports", "export-telemetry", str(src), "--output", str(out)])
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "command",
    [(str(CONSOLE_SCRIPT),), (sys.executable, "-m", "sentinellite")],
)
def test_entry_points_export_telemetry_outside_checkout(
    command: tuple[str, ...], tmp_path: Path
) -> None:
    priv = tmp_path / "priv"
    priv.mkdir()
    os.chmod(priv, 0o700)

    for label, fixture in (("v1", VALID_REPORT), ("legacy", LEGACY_REPORT)):
        src = priv / f"{label}.json"
        src.write_bytes(fixture.read_bytes())
        os.chmod(src, 0o600)
        out = priv / f"{label}-telemetry.json"

        res = subprocess.run(
            [*command, "reports", "export-telemetry", str(src), "--output", str(out)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, res.stdout + res.stderr
        assert parse_telemetry_json(out.read_bytes()).alert_count >= 1
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

        # Repeat export to same output path refuses overwrite
        dup = subprocess.run(
            [*command, "reports", "export-telemetry", str(src), "--output", str(out)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert dup.returncode != 0
        assert "Traceback" not in dup.stdout + dup.stderr
