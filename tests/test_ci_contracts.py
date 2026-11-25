"""Execute the workflow's report assertions against generated and invalid inputs."""

import json
import re
import runpy
import sys
from pathlib import Path

import pytest
import yaml

from sentinellite.pipeline.demo import run_demo
from sentinellite.reporting.notification import (
    build_notification_summary,
    write_notification_summary,
)
from sentinellite.reporting.review import load_review_report
from sentinellite.reporting.validation import (
    IncompatibleReportError,
    MalformedReportError,
    UnsupportedSchemaError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = PROJECT_ROOT / ".github/workflows/ci.yml"
REPORT_STEPS = (
    "Validate Linux authentication log fixture compatibility",
    "Validate local notification summary export",
    "Run authentication JSON explanation smoke test",
    "Validate config-driven JSON explanations",
)
COMPATIBILITY_STEP = "Validate schema-v1 and historical report compatibility"


def workflow_steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["test"]["steps"]


def python_blocks(text: str) -> list[str]:
    return re.findall(r"<<'PY'\n(.*?)\nPY", text, flags=re.DOTALL)


def report_assertions(name: str) -> str:
    step = next(step for step in workflow_steps() if step["name"] == name)
    blocks = [block for block in python_blocks(step["run"]) if "parse_report_json" in block]
    assert len(blocks) == 1
    return blocks[0]


def prepare_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    summary, _ = run_demo(tmp_path / "reports", include_explanations=True)
    report = Path(summary.report_path)
    notification = tmp_path / "notification.json"
    write_notification_summary(build_notification_summary(load_review_report(report)), notification)
    snapshot = tmp_path / "source-snapshot.bin"
    snapshot.write_bytes(report.read_bytes())
    return report, notification, snapshot


def run_python(code: str, path: Path) -> None:
    path.write_text(code, encoding="utf-8")
    runpy.run_path(str(path), run_name="__main__")


def run_assertions(
    name: str, report: Path, notification: Path, snapshot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = report_assertions(name).replace(
        "/tmp/sentinellite-config-explanation-smoke", str(report.parent)
    )
    args = [str(report.parent)]
    if name == "Validate local notification summary export":
        args = [str(report), str(notification), str(snapshot)]
    monkeypatch.setattr(sys, "argv", ["ci-report-contract", *args])
    run_python(code, report.parent.parent / "ci-report-contract.py")


@pytest.mark.parametrize("name", REPORT_STEPS)
def test_ci_generation_assertions_accept_complete_schema_v1(name: str, tmp_path: Path, monkeypatch):
    report, notification, snapshot = prepare_inputs(tmp_path)
    original = report.read_bytes()
    run_assertions(name, report, notification, snapshot, monkeypatch)
    assert report.read_bytes() == original


@pytest.mark.parametrize("name", REPORT_STEPS)
@pytest.mark.parametrize(
    ("defect", "error_type"),
    [
        ("boolean-version", IncompatibleReportError),
        ("future-version", UnsupportedSchemaError),
        ("extra-envelope-field", IncompatibleReportError),
        ("missing-alert-field", IncompatibleReportError),
        ("incomplete-explanation", IncompatibleReportError),
        ("duplicate-key", MalformedReportError),
        ("non-finite-evidence", MalformedReportError),
        ("legacy-generated-output", AssertionError),
    ],
)
def test_ci_generation_assertions_reject_contract_regressions(
    name: str, defect: str, error_type: type[Exception], tmp_path: Path, monkeypatch
) -> None:
    report, notification, snapshot = prepare_inputs(tmp_path)
    data = json.loads(report.read_bytes())
    if defect == "boolean-version":
        data["schema_version"] = True
    elif defect == "future-version":
        data["schema_version"] = 2
    elif defect == "extra-envelope-field":
        data["unexpected"] = "must not be accepted"
    elif defect == "missing-alert-field":
        del data["alerts"][-1]["evidence"]
    elif defect == "incomplete-explanation":
        del data["alerts"][-1]["explanation"]["why_it_matched"]
    elif defect == "legacy-generated-output":
        del data["schema_version"]
    elif defect == "non-finite-evidence":
        data["alerts"][-1]["evidence"]["number"] = float("nan")
    text = json.dumps(data)
    if defect == "duplicate-key":
        text = text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    report.write_text(text, encoding="utf-8")
    snapshot.write_bytes(report.read_bytes())
    with pytest.raises(error_type):
        run_assertions(name, report, notification, snapshot, monkeypatch)
    assert report.read_text(encoding="utf-8") == text


def test_ci_compatibility_assertions_accept_legacy_without_upgrading_and_reject_future(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(PROJECT_ROOT)
    run_python(report_assertions(COMPATIBILITY_STEP), tmp_path / "ci-compatibility.py")


def test_ci_quality_gates_and_embedded_python_remain_intact() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["test"]
    assert {"3.11", "3.14"} <= set(job["strategy"]["matrix"]["python-version"])
    steps = {step["name"]: step for step in job["steps"]}
    assert steps["Check installed dependencies"]["run"] == "python -m pip check"
    assert steps["Run Ruff"]["run"] == "ruff check --no-cache src tests"
    assert steps["Run Pytest"]["run"] == "PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider"
    assert steps["Build wheel"]["run"] == "python -m build --wheel"
    assert {
        "Validate wheel contents and metadata",
        "Validate wheel in an isolated environment",
        "Validate installed entry points",
        "Create and use default TOML config",
        "Run authentication scan smoke test",
        "Validate local report review commands",
        "Validate disabled process module",
        "Run process scan smoke test",
        "Run network observation smoke test",
        "Run file integrity observation smoke test",
        "Run file integrity baseline creation smoke test",
        "Run file integrity baseline scan smoke test",
        *REPORT_STEPS,
        COMPATIBILITY_STEP,
    } <= steps.keys()
    for step in steps.values():
        for block in python_blocks(step.get("run", "")):
            compile(block, f"{WORKFLOW}:{step['name']}", "exec")


def test_demo_contract_check_example_executes_against_generated_outputs(tmp_path: Path, monkeypatch):
    report, notification, _ = prepare_inputs(tmp_path)
    demo = (PROJECT_ROOT / "docs/demo-guide.md").read_text(encoding="utf-8")
    blocks = python_blocks(demo)
    assert len(blocks) == 1
    monkeypatch.setattr(sys, "argv", ["demo-contract-check", str(report), str(notification)])
    run_python(blocks[0], tmp_path / "demo-contract-check.py")
