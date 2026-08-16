import psutil

from sentinellite.collectors.process import (
    ProcessInfo,
    collect_processes,
    filter_high_resource_processes,
    filter_processes_by_keywords,
    filter_temp_path_processes,
    is_process_running_from_temp_path,
    processes_to_dicts,
)


class FakeProcess:
    def __init__(self, info):
        self.info = info


class AccessDeniedProcess:
    @property
    def info(self):
        raise psutil.AccessDenied(pid=999)


def test_collect_processes_normalizes_process_data(monkeypatch):
    fake_processes = [
        FakeProcess(
            {
                "pid": 123,
                "name": "sshd",
                "username": "root",
                "exe": "/usr/sbin/sshd",
                "cmdline": ["/usr/sbin/sshd", "-D"],
                "cpu_percent": 1.5,
                "memory_percent": 0.8,
                "status": "sleeping",
            }
        )
    ]

    def fake_process_iter(*_args, **_kwargs):
        return fake_processes

    monkeypatch.setattr(
        "sentinellite.collectors.process.psutil.process_iter",
        fake_process_iter,
    )

    processes = collect_processes()

    assert len(processes) == 1
    assert processes[0].pid == 123
    assert processes[0].name == "sshd"
    assert processes[0].username == "root"
    assert processes[0].exe == "/usr/sbin/sshd"
    assert processes[0].cmdline == ["/usr/sbin/sshd", "-D"]
    assert processes[0].cpu_percent == 1.5
    assert processes[0].memory_percent == 0.8
    assert processes[0].status == "sleeping"


def test_collect_processes_skips_inaccessible_processes(monkeypatch):
    fake_processes = [
        AccessDeniedProcess(),
        FakeProcess(
            {
                "pid": 321,
                "name": "python",
                "username": "kavisara",
                "exe": "/usr/bin/python3",
                "cmdline": ["python3", "main.py"],
                "cpu_percent": 2.0,
                "memory_percent": 1.0,
                "status": "running",
            }
        ),
    ]

    def fake_process_iter(*_args, **_kwargs):
        return fake_processes

    monkeypatch.setattr(
        "sentinellite.collectors.process.psutil.process_iter",
        fake_process_iter,
    )

    processes = collect_processes()

    assert len(processes) == 1
    assert processes[0].pid == 321


def test_is_process_running_from_temp_path_detects_tmp_executable():
    process = ProcessInfo(
        pid=444,
        name="suspicious",
        username="www-data",
        exe="/tmp/suspicious",
        cmdline=["/tmp/suspicious"],
        cpu_percent=0.0,
        memory_percent=0.0,
        status="running",
    )

    assert is_process_running_from_temp_path(process) is True


def test_filter_temp_path_processes_returns_only_temp_processes():
    normal_process = ProcessInfo(
        pid=1,
        name="systemd",
        username="root",
        exe="/usr/lib/systemd/systemd",
        cmdline=["/usr/lib/systemd/systemd"],
        cpu_percent=0.0,
        memory_percent=0.1,
        status="sleeping",
    )

    temp_process = ProcessInfo(
        pid=2,
        name="unknown",
        username="kavisara",
        exe="/tmp/unknown",
        cmdline=["/tmp/unknown"],
        cpu_percent=0.0,
        memory_percent=0.1,
        status="running",
    )

    results = filter_temp_path_processes([normal_process, temp_process])

    assert results == [temp_process]


def test_filter_high_resource_processes_detects_cpu_or_memory_threshold():
    normal_process = ProcessInfo(
        pid=10,
        name="normal",
        username="kavisara",
        exe="/usr/bin/normal",
        cmdline=["normal"],
        cpu_percent=10.0,
        memory_percent=5.0,
        status="sleeping",
    )

    high_cpu_process = ProcessInfo(
        pid=11,
        name="high-cpu",
        username="kavisara",
        exe="/usr/bin/high-cpu",
        cmdline=["high-cpu"],
        cpu_percent=90.0,
        memory_percent=5.0,
        status="running",
    )

    high_memory_process = ProcessInfo(
        pid=12,
        name="high-memory",
        username="kavisara",
        exe="/usr/bin/high-memory",
        cmdline=["high-memory"],
        cpu_percent=10.0,
        memory_percent=85.0,
        status="running",
    )

    results = filter_high_resource_processes(
        [normal_process, high_cpu_process, high_memory_process],
        cpu_threshold=80.0,
        memory_threshold=80.0,
    )

    assert results == [high_cpu_process, high_memory_process]


def test_filter_processes_by_keywords_matches_command_line():
    normal_process = ProcessInfo(
        pid=20,
        name="bash",
        username="kavisara",
        exe="/usr/bin/bash",
        cmdline=["bash"],
        cpu_percent=0.0,
        memory_percent=0.1,
        status="sleeping",
    )

    suspicious_process = ProcessInfo(
        pid=21,
        name="python",
        username="kavisara",
        exe="/usr/bin/python3",
        cmdline=["python3", "-m", "http.server"],
        cpu_percent=0.0,
        memory_percent=0.1,
        status="running",
    )

    results = filter_processes_by_keywords(
        [normal_process, suspicious_process],
        suspicious_keywords=["http.server"],
    )

    assert results == [suspicious_process]


def test_processes_to_dicts_converts_process_info_objects():
    process = ProcessInfo(
        pid=30,
        name="nginx",
        username="www-data",
        exe="/usr/sbin/nginx",
        cmdline=["nginx", "-g", "daemon off;"],
        cpu_percent=0.5,
        memory_percent=2.0,
        status="sleeping",
    )

    results = processes_to_dicts([process])

    assert results == [
        {
            "pid": 30,
            "name": "nginx",
            "username": "www-data",
            "exe": "/usr/sbin/nginx",
            "cmdline": ["nginx", "-g", "daemon off;"],
            "cpu_percent": 0.5,
            "memory_percent": 2.0,
            "status": "sleeping",
        }
    ]
