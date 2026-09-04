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
