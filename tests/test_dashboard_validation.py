"""Dashboard contract boundary and bounded local-reader regressions."""

import json
import os
import stat
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinellite.reporting import dashboard
from sentinellite.reporting.dashboard import export_dashboard, load_dashboard_data, render_dashboard
from sentinellite.reporting.review import MAX_REPORT_SIZE_BYTES
from sentinellite.reporting.validation import parse_report_json

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "report_schema"
FIXTURE_CASES = [
    ("schema_v1_alert.json", True),
    ("schema_v1_explanation.json", True),
    ("schema_v1_empty.json", True),
    ("legacy_unversioned_alert.json", True),
    ("legacy_unversioned_explanation.json", True),
    ("unsupported_schema_version.json", False),
    ("incompatible_missing_alert_field.json", False),
    ("incompatible_alert_count.json", False),
    ("incompatible_boolean_risk_score.json", False),
    ("incompatible_report_type.json", False),
    ("incompatible_incomplete_explanation.json", False),
    ("incompatible_explanation_rule_id.json", False),
    ("malformed_json_syntax.json", False),
    ("malformed_duplicate_top_level_key.json", False),
    ("malformed_duplicate_nested_key.json", False),
    ("malformed_non_finite_numbers.json", False),
]


def sample_report(versioned: bool = True) -> dict:
    name = "schema_v1_explanation.json" if versioned else "legacy_unversioned_explanation.json"
    return json.loads((FIXTURE_DIR / name).read_bytes())


def write_report(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def assert_rejected(tmp_path: Path, data: dict) -> None:
    original = write_report(tmp_path / "invalid.json", data).read_bytes()
    loaded = load_dashboard_data(tmp_path, limit=1)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (0, 1)
    assert loaded.reports == loaded.alerts == ()
    assert (tmp_path / "invalid.json").read_bytes() == original


@pytest.mark.parametrize(("filename", "valid"), FIXTURE_CASES)
def test_all_canonical_fixtures_at_dashboard_boundary(
    filename: str, valid: bool, tmp_path: Path
) -> None:
    original = (FIXTURE_DIR / filename).read_bytes()
    path = tmp_path / filename
    path.write_bytes(original)
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (int(valid), int(not valid))
    if valid:
        stored = json.loads(original)
        assert loaded.reports[0].filename == filename
        assert loaded.reports[0].alert_count == stored["alert_count"]
        assert len(loaded.alerts) == stored["alert_count"]
        if loaded.alerts:
            alert = stored["alerts"][0]
            projected = loaded.alerts[0]
            assert projected.rule_id == alert["rule_id"]
            assert projected.risk_score == "50"
            assert projected.title == alert["rule_name"]
            assert projected.source == alert["source"]
            assert projected.module == alert["category"]
            assert projected.summary == alert.get("explanation", {}).get("summary", alert["message"])
    else:
        assert loaded.reports == loaded.alerts == ()
    assert path.read_bytes() == original


def test_mixed_fixture_directory_exports_only_complete_supported_reports(tmp_path: Path) -> None:
    assert {filename for filename, _ in FIXTURE_CASES} == {
        path.name for path in FIXTURE_DIR.glob("*.json")
    }
    originals = {}
    for filename, _ in reversed(FIXTURE_CASES):
        originals[filename] = (FIXTURE_DIR / filename).read_bytes()
        (tmp_path / filename).write_bytes(originals[filename])
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (5, 11)
    assert [report.filename for report in loaded.reports] == sorted(
        filename for filename, valid in FIXTURE_CASES if valid
    )
    assert len(loaded.alerts) == 4
    output = export_dashboard(tmp_path, tmp_path / "dashboard.html")
    document = output.read_text(encoding="utf-8")
    assert "Showing 5 of 5 loaded reports" in document
    assert "Skipped files: 11" in document
    for filename, valid in FIXTURE_CASES:
        assert (filename in document) is valid
        assert (tmp_path / filename).read_bytes() == originals[filename]


@pytest.mark.parametrize("versioned", [False, True])
@pytest.mark.parametrize("location", ["report", "alert", "explanation"])
def test_every_required_field_is_checked_before_projection(
    versioned: bool, location: str, tmp_path: Path
) -> None:
    sample = sample_report(versioned)
    target = sample if location == "report" else sample["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    for field in target:
        # Removing the version is a valid transition to the legacy contract.
        if field == "schema_version" or (location == "alert" and field == "explanation"):
            continue
        data = sample_report(versioned)
        changed = data if location == "report" else data["alerts"][0]
        if location == "explanation":
            changed = changed["explanation"]
        del changed[field]
        assert_rejected(tmp_path, data)


@pytest.mark.parametrize("versioned", [False, True])
@pytest.mark.parametrize("location", ["report", "alert", "explanation"])
def test_every_contract_field_rejects_incorrect_types(
    versioned: bool, location: str, tmp_path: Path
) -> None:
    sample = sample_report(versioned)
    target = sample if location == "report" else sample["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    for field, value in target.items():
        data = sample_report(versioned)
        changed = data if location == "report" else data["alerts"][0]
        if location == "explanation":
            changed = changed["explanation"]
        changed[field] = True if type(value) is int else None
        assert_rejected(tmp_path, data)


@pytest.mark.parametrize("versioned", [False, True])
@pytest.mark.parametrize("location", ["report", "alert", "explanation"])
def test_unknown_fields_are_rejected_instead_of_projected(
    versioned: bool, location: str, tmp_path: Path
) -> None:
    data = sample_report(versioned)
    target = data if location == "report" else data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target["PRIVATE_UNKNOWN_FIELD"] = "PRIVATE_UNKNOWN_VALUE"
    assert_rejected(tmp_path, data)
    document = render_dashboard(load_dashboard_data(tmp_path))
    assert "PRIVATE_UNKNOWN" not in document


@pytest.mark.parametrize("version", [2, 3, 10**50])
def test_future_schema_never_projects_a_recognizable_or_unknown_body(
    version: int, tmp_path: Path
) -> None:
    for recognizable in (True, False):
        data = sample_report()
        data["schema_version"] = version
        data["alerts"][0]["rule_name"] = "PRIVATE_FUTURE_TITLE"
        if not recognizable:
            data["alerts"] = "PRIVATE_FUTURE_BODY"
        assert_rejected(tmp_path, data)
        assert "PRIVATE_FUTURE" not in render_dashboard(load_dashboard_data(tmp_path))


@pytest.mark.parametrize("versioned", [False, True])
def test_invalid_alert_beyond_display_limit_rejects_entire_report(
    versioned: bool, tmp_path: Path
) -> None:
    data = sample_report(versioned)
    data["alerts"][0]["rule_name"] = "PARTIAL_TITLE_MUST_NOT_APPEAR"
    data["alerts"].append({"rule_name": "INVALID_LAST_ALERT"})
    data["alert_count"] = 2
    assert_rejected(tmp_path, data)
    write_report(tmp_path / "valid.json", sample_report(versioned))
    loaded = load_dashboard_data(tmp_path, limit=1)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (1, 1)
    assert [report.filename for report in loaded.reports] == ["valid.json"]
    assert "PARTIAL_TITLE" not in render_dashboard(loaded)


@pytest.mark.parametrize("field", ["report_id", "risk_score", "summary", "synthetic"])
def test_duplicate_keys_at_each_depth_skip_whole_report(field: str, tmp_path: Path) -> None:
    text = json.dumps(sample_report())
    text = text.replace(f'"{field}":', f'"{field}": null, "{field}":', 1)
    (tmp_path / "duplicate.json").write_text(text, encoding="utf-8")
    write_report(tmp_path / "valid.json", sample_report())
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (1, 1)
    assert [report.filename for report in loaded.reports] == ["valid.json"]


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e9999"])
@pytest.mark.parametrize("field", ["risk_score", "private"])
def test_non_finite_numbers_in_scores_or_private_evidence_are_skipped(
    token: str, field: str, tmp_path: Path
) -> None:
    data = sample_report()
    target = data["alerts"][0] if field == "risk_score" else data["alerts"][0]["evidence"]
    target[field] = "TOKEN"
    (tmp_path / "non-finite.json").write_text(
        json.dumps(data).replace('"TOKEN"', token), encoding="utf-8"
    )
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (0, 1)
    assert loaded.reports == loaded.alerts == ()


@pytest.mark.parametrize("encoding", ["invalid", "utf-16", "utf-32", "surrogate"])
def test_invalid_unicode_does_not_hide_valid_reports(encoding: str, tmp_path: Path) -> None:
    text = json.dumps(sample_report())
    if encoding == "invalid":
        encoded = text.encode() + b"\xff"
    elif encoding == "surrogate":
        data = sample_report()
        data["alerts"][0]["evidence"]["private"] = "\ud800"
        encoded = json.dumps(data).encode()
    else:
        encoded = text.encode(encoding)
    (tmp_path / "invalid.json").write_bytes(encoded)
    write_report(tmp_path / "valid.json", sample_report())
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (1, 1)
    assert [report.filename for report in loaded.reports] == ["valid.json"]


@pytest.mark.parametrize("versioned", [False, True])
def test_ordering_is_stable_with_equal_report_times_and_alert_ties(
    versioned: bool, tmp_path: Path
) -> None:
    for name in ("c.json", "b.json", "a.json"):
        data = sample_report(versioned)
        data["alerts"] = []
        for index in range(3):
            alert = sample_report(versioned)["alerts"][0]
            alert["rule_name"] = f"{name}-{index}"
            data["alerts"].append(alert)
        data["alert_count"] = 3
        write_report(tmp_path / name, data)
    for _ in range(2):
        loaded = load_dashboard_data(tmp_path, limit=2)
        assert (loaded.reports_loaded, loaded.reports_skipped) == (3, 0)
        assert [report.filename for report in loaded.reports] == ["a.json", "b.json"]
        assert [alert.title for alert in loaded.alerts] == ["a.json-0", "a.json-1"]
        assert [alert.title for alert in loaded.reports[1].alerts] == ["b.json-0", "b.json-1"]


@pytest.mark.parametrize("versioned", [False, True])
def test_compatible_lowercase_utc_and_empty_display_fields(versioned: bool, tmp_path: Path) -> None:
    data = sample_report(versioned)
    data["generated_at"] = "2026-01-01t00:00:00z"
    for field in ("rule_name", "source", "category", "event_type", "message", "description"):
        data["alerts"][0][field] = ""
    del data["alerts"][0]["explanation"]
    write_report(tmp_path / "report.json", data)
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (1, 0)
    assert loaded.reports[0].generated_at == datetime(2026, 1, 1, tzinfo=UTC)
    alert = loaded.alerts[0]
    assert alert.timestamp == loaded.reports[0].generated_at
    assert alert.title == "Untitled alert"
    assert alert.source == alert.module == alert.summary == "—"


@pytest.mark.parametrize("valid", [False, True])
def test_canonical_parser_receives_complete_bytes_after_descriptor_closes(
    valid: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_report(tmp_path / "report.json", sample_report())
    if not valid:
        path.write_bytes(path.read_bytes() + b"{invalid")
    original = path.read_bytes()
    descriptor = None
    original_open = dashboard.os.open
    parsed = []

    def tracked_open(path, flags):
        nonlocal descriptor
        assert flags & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)
        assert flags & getattr(os, "O_NONBLOCK", 0) == getattr(os, "O_NONBLOCK", 0)
        descriptor = original_open(path, flags)
        return descriptor

    def tracked_parser(encoded):
        assert type(encoded) is bytes and encoded == original
        with pytest.raises(OSError):
            os.fstat(descriptor)
        parsed.append(encoded)
        return parse_report_json(encoded)

    monkeypatch.setattr(dashboard.os, "open", tracked_open)
    monkeypatch.setattr(dashboard, "parse_report_json", tracked_parser)
    loaded = load_dashboard_data(tmp_path, limit=1)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (int(valid), int(not valid))
    assert parsed == [original]


@pytest.mark.parametrize("versioned", [False, True])
def test_projection_preserves_stored_scores_summary_and_privacy(
    versioned: bool, tmp_path: Path
) -> None:
    data = sample_report(versioned)
    data["report_id"] = "PRIVATE_REPORT_ID"
    alert = data["alerts"][0]
    text = '<script>saved & "quoted"</script>'
    alert.update(
        rule_name=text,
        source=text,
        category=text,
        severity="low",
        base_score=99,
        risk_score=7,
        risk_level="critical",
        recommendation="PRIVATE_RECOMMENDATION",
        evidence={"PRIVATE_EVIDENCE_KEY": "PRIVATE_EVIDENCE_VALUE"},
    )
    explanation = alert["explanation"]
    explanation.update(
        summary=text,
        title="PRIVATE_EXPLANATION_TITLE",
        why_it_matched="PRIVATE_EXPLANATION_REASON",
        possible_causes=["PRIVATE_EXPLANATION_CAUSE"],
        recommended_actions=["PRIVATE_EXPLANATION_ACTION"],
        evidence_summary={"PRIVATE_SUMMARY_KEY": "PRIVATE_SUMMARY_VALUE"},
    )
    path = write_report(tmp_path / "report.json", data)
    original = path.read_bytes()
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (1, 0)
    projected = loaded.alerts[0]
    assert projected.risk_score == "7"
    assert projected.severity == "low"
    assert projected.summary == projected.title == projected.source == projected.module == text
    document = render_dashboard(loaded)
    assert escape(text, quote=True) in document
    assert text not in document
    assert "PRIVATE_" not in document
    assert str(tmp_path) not in document
    assert path.read_bytes() == original


def test_exact_two_mib_boundary_is_accepted_but_one_extra_byte_is_skipped(tmp_path: Path) -> None:
    assert MAX_REPORT_SIZE_BYTES == 2 * 1024 * 1024
    encoded = json.dumps(sample_report()).encode()
    boundary = encoded + b" " * (MAX_REPORT_SIZE_BYTES - len(encoded))
    (tmp_path / "boundary.json").write_bytes(boundary)
    (tmp_path / "oversized.json").write_bytes(boundary + b" ")
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (1, 1)
    assert [report.filename for report in loaded.reports] == ["boundary.json"]


@pytest.mark.parametrize("growing", [False, True])
def test_oversized_files_reject_before_parser_and_close_descriptor(
    growing: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_report(tmp_path / "large.json", sample_report())
    if not growing:
        with path.open("wb") as stream:
            stream.truncate(MAX_REPORT_SIZE_BYTES + 1)
    original_fdopen = dashboard.os.fdopen
    streams = []
    reads = []

    class GrowingFile:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            reads.append(size)
            return b" " * size

    def tracked_fdopen(descriptor, mode):
        stream = original_fdopen(descriptor, mode)
        streams.append(stream)
        return GrowingFile(stream) if growing else stream

    def forbidden(*args):
        raise AssertionError("Oversized files must be rejected before parsing")

    monkeypatch.setattr(dashboard.os, "fdopen", tracked_fdopen)
    monkeypatch.setattr(dashboard, "parse_report_json", forbidden)
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (0, 1)
    assert reads == ([MAX_REPORT_SIZE_BYTES + 1] if growing else [])
    assert len(streams) == 1 and streams[0].closed


def test_symlink_substituted_after_discovery_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = write_report(tmp_path / "target.txt", sample_report())
    path = write_report(tmp_path / "report.json", sample_report())
    original_discover = dashboard.discover_report_paths

    def substitute(directory):
        paths = original_discover(directory)
        path.unlink()
        path.symlink_to(target)
        return paths

    def forbidden(*args):
        raise AssertionError("Report symlinks must not be opened")

    monkeypatch.setattr(dashboard, "discover_report_paths", substitute)
    monkeypatch.setattr(dashboard.os, "open", forbidden)
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (0, 1)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW is unavailable")
def test_symlink_substituted_at_open_is_blocked_by_no_follow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = write_report(tmp_path / "target.txt", sample_report())
    path = write_report(tmp_path / "report.json", sample_report())
    original_open = dashboard.os.open

    def substitute(path_arg, flags):
        path.unlink()
        path.symlink_to(target)
        return original_open(path_arg, flags)

    monkeypatch.setattr(dashboard.os, "open", substitute)
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (0, 1)


def test_non_regular_descriptor_is_rejected_and_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "fifo.json"
    os.mkfifo(path)
    original_fstat = dashboard.os.fstat
    descriptors = []

    def tracked_fstat(descriptor):
        descriptors.append(descriptor)
        result = original_fstat(descriptor)
        assert stat.S_ISFIFO(result.st_mode)
        return result

    monkeypatch.setattr(dashboard, "discover_report_paths", lambda directory: [path])
    isolated_os = SimpleNamespace(**vars(dashboard.os))
    isolated_os.fstat = tracked_fstat
    monkeypatch.setattr(dashboard, "os", isolated_os)
    assert os.fstat is original_fstat
    loaded = load_dashboard_data(tmp_path)
    assert (loaded.reports_loaded, loaded.reports_skipped) == (0, 1)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        original_fstat(descriptors[0])
