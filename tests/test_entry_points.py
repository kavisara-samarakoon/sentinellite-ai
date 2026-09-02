import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

CONSOLE_SCRIPT = Path(sysconfig.get_path("scripts")) / "sentinellite"
CONSOLE_COMMAND = (str(CONSOLE_SCRIPT),)
MODULE_COMMAND = (sys.executable, "-m", "sentinellite")
EXPECTED_COMMANDS = {
    "auth-sources",
    "baseline-files",
    "config-init",
    "reports",
    "scan-auth",
    "scan-files",
    "scan-files-baseline",
    "scan-network",
    "scan-process",
}


def run_entry_point(
    command: tuple[str, ...],
    *arguments: str,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_console_script_is_installed() -> None:
    assert CONSOLE_SCRIPT.is_file()


def test_entry_point_versions_agree_outside_checkout(tmp_path: Path) -> None:
    console_result = run_entry_point(
        CONSOLE_COMMAND,
        "--version",
        cwd=tmp_path,
    )
    module_result = run_entry_point(
        MODULE_COMMAND,
        "--version",
        cwd=tmp_path,
    )

    expected_output = "SentinelLite AI v0.9.0-alpha\n"
    assert console_result.returncode == 0
    assert module_result.returncode == 0
    assert console_result.stdout == expected_output
    assert module_result.stdout == expected_output
    assert console_result.stderr == ""
    assert module_result.stderr == ""


@pytest.mark.parametrize("command", [CONSOLE_COMMAND, MODULE_COMMAND])
def test_bare_entry_point_status_works_outside_checkout(
    command: tuple[str, ...],
    tmp_path: Path,
) -> None:
    result = run_entry_point(command, cwd=tmp_path)

    assert result.returncode == 0
    assert "SentinelLite AI v0.9.0-alpha" in result.stdout
    assert "Status: READY" in result.stdout
    assert "Configuration error" not in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("command", [CONSOLE_COMMAND, MODULE_COMMAND])
def test_entry_points_expose_expected_command_tree(
    command: tuple[str, ...],
    tmp_path: Path,
) -> None:
    result = run_entry_point(command, "--help", cwd=tmp_path)

    assert result.returncode == 0
    for command_name in EXPECTED_COMMANDS:
        assert command_name in result.stdout
