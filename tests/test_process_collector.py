import psutil

from sentinellite.collectors.process import (
    ProcessInfo,
    collect_processes,
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


def test_collect_processes_uses_defaults_for_missing_values(monkeypatch):
    fake_processes = [FakeProcess({})]

    def fake_process_iter(*_args, **_kwargs):
        return fake_processes

    monkeypatch.setattr(
        "sentinellite.collectors.process.psutil.process_iter",
        fake_process_iter,
    )

    processes = collect_processes()

    assert processes == [
        ProcessInfo(
            pid=0,
            name="unknown",
            username=None,
            exe=None,
            cmdline=[],
            cpu_percent=0.0,
            memory_percent=0.0,
            status=None,
        )
    ]


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
