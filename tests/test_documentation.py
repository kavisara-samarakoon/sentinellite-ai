import json
import re
from pathlib import Path

from sentinellite.reporting.schema import ReportContract
from sentinellite.reporting.validation import parse_report_json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CURRENT_DOCUMENTS = (
    PROJECT_ROOT / "README.md",
    PROJECT_ROOT / "CONTRIBUTING.md",
    PROJECT_ROOT / "SECURITY.md",
    PROJECT_ROOT / "docs/demo-guide.md",
    PROJECT_ROOT / "docs/linux-validation.md",
    PROJECT_ROOT / "docs/data-contracts.md",
    PROJECT_ROOT / "docs/release-checklist.md",
    PROJECT_ROOT / "docs/release-notes-v1.1.0-beta.md",
    PROJECT_ROOT / "docs/release-notes-v1.2.0-beta.md",
    PROJECT_ROOT / "docs/release-notes-v1.3.0-beta.md",
    PROJECT_ROOT / "docs/cloud/vm-validation.md",
    PROJECT_ROOT / "docs/cloud/compatibility-matrix.md",
    PROJECT_ROOT / "docs/cloud/evidence-checklist.md",
    PROJECT_ROOT / "docs/integrations/arm-secnet.md",
    PROJECT_ROOT / "tests/fixtures/report_schema/README.md",
)
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^]]+\]\(([^)]+)\)")
REPOSITORY_URL = "https://github.com/kavisara-samarakoon/sentinellite-ai"
V1_3_RELEASE_URL = f"{REPOSITORY_URL}/releases/tag/v1.3.0-beta"
V1_3_ARM64_ISSUE_URL = f"{REPOSITORY_URL}/issues/17"
V1_3_WHEEL = "sentinellite_ai-1.3.0b0-py3-none-any.whl"


def test_current_document_relative_links_exist() -> None:
    for document in CURRENT_DOCUMENTS:
        text = document.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK_PATTERN.findall(text):
            if target.startswith(("http://", "https://", "#")):
                continue
            relative_path = target.split("#", maxsplit=1)[0]
            assert (document.parent / relative_path).exists(), (
                f"Broken link in {document.relative_to(PROJECT_ROOT)}: {target}"
            )


def test_readme_exposes_current_install_and_release_documents() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "https://github.com/kavisara-samarakoon/sentinellite-ai.git" in readme
    assert "on-demand, local, defensive" in readme
    assert "docs/data-contracts.md" in readme
    assert "docs/release-checklist.md" in readme
    assert "production EDR" in readme
    assert "docs/release-notes-v1.3.0-beta.md" in readme
    assert "`v1.3.0-beta` (package version `1.3.0b0`) was published as a" in readme
    assert "docs/release-notes-v1.2.0-beta.md" in readme
    assert "releases/tag/v1.2.0-beta" in readme
    assert "feature/v1.3-report-schema-v1" not in readme
    assert "releases/tag/v1.1.0-beta" in readme
    assert "docs/release-notes-v1.1.0-beta.md" in readme
    assert "wheel predates the dashboard exporter" in readme
    assert "current published milestone is `v0.9.0-alpha`" not in readme.lower()
    assert "Published `v1.2.0-beta` artifacts retain their historical unversioned report format" in readme


def test_readme_and_lab_install_the_published_v1_3_wheel() -> None:
    for path, heading in (
        ("README.md", "## Install from GitHub Release\n"),
        ("docs/integrations/arm-secnet.md", "## Install from a GitHub Release Wheel\n"),
    ):
        document = (PROJECT_ROOT / path).read_text(encoding="utf-8")
        install = document.split(heading, 1)[1].split("\n## ", 1)[0]
        assert V1_3_RELEASE_URL in install, path
        assert f"python -m pip install ./{V1_3_WHEEL}" in install, path
        assert "`SHA256SUMS.txt`" in install, path
        assert "`SentinelLite AI v1.3.0-beta`" in install, path
        assert "1.2.0b0" not in install, path


def test_beta_release_notes_are_published_and_safety_scoped() -> None:
    release_notes = (
        PROJECT_ROOT / "docs/release-notes-v1.2.0-beta.md"
    ).read_text(encoding="utf-8")
    normalized_notes = " ".join(release_notes.lower().split())

    assert "`v1.2.0-beta` is published as a github pre-release" in normalized_notes
    assert "releases/tag/v1.2.0-beta" in release_notes
    assert "2026-09-12T05:37:29Z" in release_notes
    assert "548c4ce46de9dbbf52cf43fd9f5cb541224fa03f" in release_notes
    assert "d60813350cbb2b1e09ed99c6afa15442f280e043" in release_notes
    assert "fc8c647921d1d2575cb0ac25e1a7f32191e8ea8e0363a90a4728bf59dae4ba15" in release_notes
    assert "c3fa1c8e56e179b836f7533d84b5ee2383f75eb15b1f39a6892eb57da7f77ee5" in release_notes
    assert "276b978ba01b5e7b6d8232c778f647cd499e70f3e23d48d15dd9de0e7fd51afd" in release_notes
    assert "pending" not in normalized_notes
    assert "release candidate" not in normalized_notes
    assert "sentinellite dashboard export" in release_notes
    assert "d1775f0ca09d714f5ed9d681af90f216c1c39e8e" in release_notes
    assert "does not prove universal arm64" in normalized_notes
    assert "not a production edr release" in normalized_notes
    assert "no real ai or llm execution" in normalized_notes
    assert "no external notification delivery" in normalized_notes
    assert "no daemon, scheduler, background service" in normalized_notes
    assert "no active network scanning" in normalized_notes
    assert "no automatic remediation" in normalized_notes


def test_v1_3_release_notes_record_publication_and_verified_assets() -> None:
    release_notes = (
        PROJECT_ROOT / "docs/release-notes-v1.3.0-beta.md"
    ).read_text(encoding="utf-8")
    normalized_notes = " ".join(release_notes.lower().replace("**", "").split())

    assert V1_3_RELEASE_URL in release_notes
    assert "`v1.3.0-beta` is published as a [github pre-release]" in normalized_notes
    for field, value in (
        ("Published at", "2026-11-27T07:45:25Z"),
        ("Draft", "false"),
        ("Prerelease", "true"),
        ("Release ID", "460294277"),
        ("Git tag", "v1.3.0-beta"),
        ("Annotated tag SHA", "b13fe9c6030b2422ab45a7df8060f133fa452f8a"),
        ("Tag target commit", "bf84cf93b40fa73f6489cc4312b2769bcb93204f"),
    ):
        assert f"| {field} | `{value}` |" in release_notes
    for asset, digest in (
        (V1_3_WHEEL, "02fb7409a3e071d561700b9783af2136307669aaa332260d4324e20ea3c0dab3"),
        (
            "sentinellite_ai-1.3.0b0.tar.gz",
            "c17e285ccf6e99cad8c8e6e2f5ef284da542adc6312fd4f9fd843128df0f128d",
        ),
        ("SHA256SUMS.txt", "9c18c75a257c7c7d0668200c0a23b419f781041055bef64c8a93f9f25ec24fc4"),
    ):
        assert f"| `{asset}` | `{digest}` |" in release_notes
    assert "all three uploaded assets were downloaded and checksum-verified" in normalized_notes
    assert "ubuntu x86-64 ci passed on python 3.11 and 3.14" in normalized_notes
    assert "macos 27.2.1 arm64 with python 3.14.6 and 1,991 tests" in normalized_notes
    assert "one report, three alerts, highest severity medium, and zero skipped files" in (
        normalized_notes
    )
    for stale_status in ("release candidate in preparation", "not yet published", "pending"):
        assert stale_status not in normalized_notes


def test_v1_3_arm64_deferral_remains_release_specific() -> None:
    for path in (
        "docs/release-notes-v1.3.0-beta.md",
        "docs/release-checklist.md",
        "docs/integrations/arm-secnet.md",
    ):
        document = (PROJECT_ROOT / path).read_text(encoding="utf-8")
        normalized = " ".join(document.lower().split())
        assert V1_3_ARM64_ISSUE_URL in document, path
        assert "on november 27, 2026, the owner deferred exact-wheel ubuntu arm64 validation" in (
            normalized
        ), path
        assert "vm was unavailable" in normalized, path
        assert "unverified" in normalized, path
        assert re.search(r"exception.{0,40}v1\.3\.0-beta|release-specific exception", normalized), path
        assert "future release" in normalized, path


def test_v1_3_release_notes_are_compatibility_and_safety_scoped() -> None:
    release_notes = (
        PROJECT_ROOT / "docs/release-notes-v1.3.0-beta.md"
    ).read_text(encoding="utf-8")
    normalized_notes = " ".join(release_notes.lower().split())

    assert "1.3.0-beta" in release_notes
    assert "1.3.0b0" in release_notes
    assert "schema_version" in release_notes
    assert "legacy-unversioned" in release_notes
    assert "parse_report_json()" in release_notes
    assert "historical-format replicas" in normalized_notes
    assert "do not claim universal linux or arm64 compatibility" in normalized_notes
    assert "not a production edr release" in normalized_notes
    assert "no real ai or llm execution" in normalized_notes
    assert "no external notification delivery" in normalized_notes
    assert "no daemon, scheduler, background service" in normalized_notes
    assert "no active network scanning" in normalized_notes
    assert "no automatic remediation" in normalized_notes
    assert "feature/v1.3-report-schema-v1" not in release_notes


def test_data_contract_documentation_covers_v1_legacy_and_consumer_outcomes() -> None:
    contracts = (PROJECT_ROOT / "docs/data-contracts.md").read_text(
        encoding="utf-8"
    )
    normalized_contracts = " ".join(contracts.split())

    assert "exactly these six top-level fields" in contracts
    for field_name in (
        "schema_version",
        "report_id",
        "report_type",
        "generated_at",
        "alert_count",
        "alerts",
    ):
        assert f"- `{field_name}`" in contracts
    assert "There is no top-level `explanations` field" in contracts
    assert "`schema_version` must be the integer `1`, not a boolean" in contracts
    assert "complete historical report has exactly the five envelope fields" in contracts
    assert "does not add a version or modify its source file" in normalized_contracts
    assert "parse_report_json()" in contracts
    for classification in ("valid (v1)", "valid (legacy)", "unsupported", "invalid"):
        assert f"`{classification}`" in contracts
    assert "exits with code 1 if any" in contracts
    assert "Skipped files" in contracts
    assert "2 MiB" in contracts
    assert "Future report bodies are" in contracts
    assert "notification summary is a separate artifact" in contracts.lower()
    assert "`schema_version` remains the integer `1`" in contracts
    assert "At most 20 alerts are included" in contracts


def test_documented_report_and_explanation_examples_are_complete_and_valid() -> None:
    contracts = (PROJECT_ROOT / "docs/data-contracts.md").read_text(encoding="utf-8")
    examples = re.findall(r"```json\n(.*?)\n```", contracts, flags=re.DOTALL)
    assert len(examples) == 3
    report = parse_report_json(examples[0])
    assert report.contract is ReportContract.SCHEMA_V1
    assert type(report.schema_version) is int and report.schema_version == 1
    explained = report.to_dict()
    explained["alerts"][0]["explanation"] = json.loads(examples[1])
    assert parse_report_json(json.dumps(explained)).contract is ReportContract.SCHEMA_V1
    legacy = report.to_dict()
    del legacy["schema_version"]
    validated = parse_report_json(json.dumps(legacy))
    assert validated.contract is ReportContract.LEGACY_UNVERSIONED
    assert "schema_version" not in validated.to_dict()


def test_demo_uses_fixture_first_non_destructive_flow() -> None:
    demo = (PROJECT_ROOT / "docs/demo-guide.md").read_text(encoding="utf-8")

    assert "Install the published `v1.3.0-beta` wheel" in demo
    assert "`SentinelLite AI v1.3.0-beta`" in demo
    for command in (
        "sentinellite --version",
        "sentinellite auth-sources list",
        "sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log",
        "sentinellite reports list",
        "sentinellite reports show",
        "sentinellite reports export-notification",
    ):
        assert command in demo
    assert "mktemp -d /tmp/sentinellite-demo.XXXXXX" in demo
    assert "rm -rf" not in demo
    assert "sentinellite scan-auth /var/log" not in demo
    assert "sudo sentinellite" not in demo


def test_only_packaged_internal_yaml_remains_and_uses_passive_wording() -> None:
    root_yaml = PROJECT_ROOT / "config/default.yaml"
    packaged_yaml = PROJECT_ROOT / "src/sentinellite/config/default.yaml"
    packaged_text = packaged_yaml.read_text(encoding="utf-8").lower()

    assert not root_yaml.exists()
    assert packaged_yaml.is_file()
    assert "open ports" not in packaged_text
    assert "active network connection metadata" in packaged_text


def test_cloud_vm_validation_docs_record_provenance_and_boundaries() -> None:
    vm_val = (PROJECT_ROOT / "docs/cloud/vm-validation.md").read_text(encoding="utf-8")
    matrix = (PROJECT_ROOT / "docs/cloud/compatibility-matrix.md").read_text(
        encoding="utf-8"
    )
    checklist = (PROJECT_ROOT / "docs/cloud/evidence-checklist.md").read_text(
        encoding="utf-8"
    )

    assert V1_3_RELEASE_URL in vm_val
    assert V1_3_WHEEL in vm_val
    assert "bf84cf93b40fa73f6489cc4312b2769bcb93204f" in vm_val
    assert "02fb7409a3e071d561700b9783af2136307669aaa332260d4324e20ea3c0dab3" in vm_val
    assert "c17e285ccf6e99cad8c8e6e2f5ef284da542adc6312fd4f9fd843128df0f128d" in vm_val
    assert "9c18c75a257c7c7d0668200c0a23b419f781041055bef64c8a93f9f25ec24fc4" in vm_val
    assert "--ignore-missing" not in vm_val
    assert "unset PYTHONPATH PYTHONHOME PYTHONOPTIMIZE" in vm_val
    assert "Content-Security-Policy" in vm_val
    assert "Total reports loaded" in vm_val
    assert "Skipped files: 0." in vm_val
    assert "rm -rf" not in vm_val
    assert "umask 077" in vm_val
    assert "never run SentinelLite as `root`" in vm_val
    assert "no public dashboard HTTP port" in vm_val
    assert "FIM-004" in vm_val
    assert "RETAINED_WORKSPACE=" in vm_val
    assert "scan-auth /var/log" not in vm_val
    assert V1_3_ARM64_ISSUE_URL in matrix
    assert "Does **not** establish Azure runtime" in matrix
    assert "umask 077" in checklist
    assert "interactive browser rendering" in checklist
    assert "FIM-004" in checklist
