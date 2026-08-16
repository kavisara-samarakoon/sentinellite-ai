from sentinellite.collectors.system import SystemInfo, collect_system_info, get_runtime_mode


def test_runtime_mode_linux() -> None:
    assert get_runtime_mode("Linux") == "Linux target environment"


def test_runtime_mode_macos() -> None:
    assert get_runtime_mode("Darwin") == "macOS development environment"


def test_runtime_mode_unknown() -> None:
    assert get_runtime_mode("Windows") == "Unsupported or untested environment"


def test_collect_system_info_returns_system_info() -> None:
    system_info = collect_system_info()

    assert isinstance(system_info, SystemInfo)
    assert system_info.hostname
    assert system_info.operating_system
    assert system_info.architecture
    assert system_info.python_version


def test_system_info_to_dict() -> None:
    system_info = collect_system_info()
    system_info_dict = system_info.to_dict()

    assert isinstance(system_info_dict, dict)
    assert "hostname" in system_info_dict
    assert "operating_system" in system_info_dict
    assert "architecture" in system_info_dict
