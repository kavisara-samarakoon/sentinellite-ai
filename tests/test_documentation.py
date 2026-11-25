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
    PROJECT_ROOT / "docs/integrations/arm-secnet.md",
    PROJECT_ROOT / "tests/fixtures/report_schema/README.md",
)
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^]]+\]\(([^)]+)\)")


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
    assert "The current version is `v1.2.0-beta`" in readme
    assert "docs/release-notes-v1.2.0-beta.md" in readme
    assert "current published\n[GitHub pre-release]" in readme
    assert "releases/tag/v1.2.0-beta" in readme
    assert "release candidate" not in readme.lower()
    assert "pending" not in readme.lower()
    assert "releases/tag/v1.1.0-beta" in readme
    assert "previous published release was\n[v1.1.0-beta]" in readme
    assert "current published milestone is `v0.9.0-alpha`" not in readme.lower()
    assert "Unreleased `v1.3.0-beta` development for Issue #14" in readme
    assert "Published `v1.2.0-beta` artifacts retain their historical report format" in readme
    assert "Package and CLI version metadata still display `v1.2.0-beta`" in readme


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
