import platform
import socket
import sys
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SystemInfo:
    hostname: str
    operating_system: str
    os_release: str
    architecture: str
    python_version: str
    runtime_mode: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def get_runtime_mode(os_name: str | None = None) -> str:
    detected_os = os_name or platform.system()

    if detected_os == "Linux":
        return "Linux target environment"

    if detected_os == "Darwin":
        return "macOS development environment"

    return "Unsupported or untested environment"


def collect_system_info() -> SystemInfo:
    return SystemInfo(
        hostname=socket.gethostname(),
        operating_system=platform.system(),
        os_release=platform.release(),
        architecture=platform.machine(),
        python_version=sys.version.split()[0],
        runtime_mode=get_runtime_mode(),
    )
