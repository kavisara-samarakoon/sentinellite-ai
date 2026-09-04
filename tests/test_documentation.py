import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CURRENT_DOCUMENTS = (
    PROJECT_ROOT / "README.md",
    PROJECT_ROOT / "CONTRIBUTING.md",
    PROJECT_ROOT / "SECURITY.md",
    PROJECT_ROOT / "docs/demo-guide.md",
    PROJECT_ROOT / "docs/linux-validation.md",
    PROJECT_ROOT / "docs/data-contracts.md",
    PROJECT_ROOT / "docs/release-checklist.md",
    PROJECT_ROOT / "docs/release-notes-v1.0.0-beta.md",
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
    assert "The current version is `v1.0.0-beta`" in readme
    assert "not yet published as a\nGitHub release" in readme
    assert "previous published milestone is `v0.9.0-alpha`" in readme
    assert "current published milestone is `v0.9.0-alpha`" not in readme.lower()


def test_beta_release_notes_remain_in_development_and_safety_scoped() -> None:
    release_notes = (
        PROJECT_ROOT / "docs/release-notes-v1.0.0-beta.md"
    ).read_text(encoding="utf-8")
    normalized_notes = " ".join(release_notes.lower().split())

    assert "`v1.0.0-beta` is in development" in normalized_notes
    assert "not yet published as a github release" in normalized_notes
    assert "not a production edr release" in normalized_notes
    assert "no real ai or llm execution" in normalized_notes
    assert "no external notification delivery" in normalized_notes
    assert "no daemon, scheduler, background service" in normalized_notes
    assert "no active network scanning" in normalized_notes
    assert "no automatic remediation" in normalized_notes


def test_beta_data_contract_documentation_preserves_existing_schemas() -> None:
    contracts = (PROJECT_ROOT / "docs/data-contracts.md").read_text(
        encoding="utf-8"
    )

    assert "exactly these five top-level fields" in contracts
    for field_name in (
        "report_id",
        "report_type",
        "generated_at",
        "alert_count",
        "alerts",
    ):
        assert f"- `{field_name}`" in contracts
    assert "There is no top-level `explanations` field" in contracts
    assert "does not add a top-level `schema_version`" in contracts
    assert "notification summary is a separate artifact" in contracts.lower()
    assert "`schema_version` remains the integer `1`" in contracts
    assert "At most 20 alerts are included" in contracts


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
