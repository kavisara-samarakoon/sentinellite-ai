"""Local installation checks; no observation, log scanning or network activity."""

import platform
import sys
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal

from sentinellite import __version__
from sentinellite.config import ConfigError, default_config, load_config

REQUIRED_DEPENDENCIES = (
    ("psutil", "psutil"),
    ("PyYAML", "yaml"),
    ("rich", "rich"),
    ("typer", "typer"),
)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: Literal["PASS", "WARNING", "FAIL"]
    detail: str


def run_doctor(output_dir: Path) -> list[DoctorCheck]:
    """Check the runtime and create, write, then remove a temporary output probe."""
    system = platform.system()
    architecture = platform.machine()
    checks = [
        DoctorCheck("SentinelLite version", "PASS", __version__),
        DoctorCheck(
            "Python version",
            "PASS" if sys.version_info >= (3, 11) else "FAIL",
            f"{platform.python_version()} (requires 3.11 or newer)",
        ),
        DoctorCheck(
            "Platform/system",
            "PASS" if system == "Linux" else "WARNING",
            f"{system or 'unknown'} {platform.release()}"
            + (
                "; endpoint observation targets Linux. Demo uses synthetic data."
                if system != "Linux"
                else ""
            ),
        ),
        DoctorCheck(
            "Machine architecture",
            "PASS" if architecture else "WARNING",
            architecture or "Could not determine architecture.",
        ),
    ]

    try:
        load_config()
        default_config()
    except (ConfigError, ImportError, OSError, RuntimeError) as error:
        checks.append(DoctorCheck("Default config", "FAIL", str(error)))
    else:
        checks.append(DoctorCheck("Default config", "PASS", "Packaged defaults loaded."))

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(prefix=".sentinellite-doctor-", dir=output_dir) as probe:
            probe.write(b"SentinelLite local write check\n")
            probe.flush()
    except OSError as error:
        checks.append(DoctorCheck("Report output directory", "FAIL", f"{output_dir}: {error}"))
    else:
        checks.append(
            DoctorCheck(
                "Report output directory",
                "PASS",
                f"{output_dir}: writable; temporary file removed.",
            )
        )

    for name, module_name in REQUIRED_DEPENDENCIES:
        try:
            import_module(module_name)
        except (ImportError, OSError, RuntimeError) as error:
            # Include binary loading failures and continue checking other dependencies.
            checks.append(DoctorCheck(f"Dependency {name}", "FAIL", str(error)))
        else:
            checks.append(DoctorCheck(f"Dependency {name}", "PASS", "Import successful."))

    return checks
