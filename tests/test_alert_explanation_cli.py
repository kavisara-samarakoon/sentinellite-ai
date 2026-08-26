import socket
import subprocess
from io import StringIO

import pytest
from rich.console import Console
from rich.panel import Panel

import sentinellite.explanations.cli as explanation_cli
from sentinellite.explanations import (
    AlertExplanation,
    build_explanation_panel,
    build_explanation_panels,
    explanation_has_displayable_evidence,
)


def create_explanation(
    rule_id: str = "AUTH-001",
    evidence_summary: dict[str, object] | None = None,
) -> AlertExplanation:
    return AlertExplanation(
        rule_id=rule_id,
        title="Failed SSH Login Attempt",
        summary="A failed SSH login attempt was observed and may require review.",
        why_it_matched="The authentication event reported a failed SSH login attempt.",
        possible_causes=["mistyped password", "automated login attempt"],
        recommended_actions=[
            "review the source address",
            "check for repeated authentication failures",
        ],
        evidence_summary={} if evidence_summary is None else evidence_summary,
        confidence="medium",
    )


def render_panel(panel: Panel) -> str:
    output = StringIO()
    console = Console(
        file=output,
        width=120,
        force_terminal=False,
        color_system=None,
    )
    console.print(panel)
    return output.getvalue()


def test_build_explanation_panel_returns_rich_panel() -> None:
    assert isinstance(build_explanation_panel(create_explanation()), Panel)


def test_panel_renderable_includes_explanation_fields_and_guidance() -> None:
    rendered = render_panel(build_explanation_panel(create_explanation()))

    assert "AUTH-001" in rendered
    assert "Failed SSH Login Attempt" in rendered
    assert "A failed SSH login attempt was observed and may require review." in rendered
    assert "The authentication event reported a failed SSH login attempt." in rendered
    assert "MEDIUM" in rendered
    assert "Possible causes" in rendered
    assert "mistyped password" in rendered
    assert "automated login attempt" in rendered
    assert "Recommended actions" in rendered
    assert "review the source address" in rendered
    assert "check for repeated authentication failures" in rendered


def test_panel_includes_evidence_only_when_non_empty() -> None:
    without_evidence = create_explanation()
    with_evidence = create_explanation(
        evidence_summary={"source_address": "192.0.2.10", "attempt_count": 3}
    )

    rendered_without_evidence = render_panel(build_explanation_panel(without_evidence))
    rendered_with_evidence = render_panel(build_explanation_panel(with_evidence))

    assert explanation_has_displayable_evidence(without_evidence) is False
    assert "Evidence summary" not in rendered_without_evidence
    assert explanation_has_displayable_evidence(with_evidence) is True
    assert "Evidence summary" in rendered_with_evidence
    assert "source_address" in rendered_with_evidence
    assert "192.0.2.10" in rendered_with_evidence
    assert "attempt_count" in rendered_with_evidence


def test_build_explanation_panels_preserves_order() -> None:
    explanations = [
        create_explanation("AUTH-001"),
        create_explanation("FIM-004"),
        create_explanation("CUSTOM-001"),
    ]

    panels = build_explanation_panels(explanations)

    assert len(panels) == 3
    assert "AUTH-001" in render_panel(panels[0])
    assert "FIM-004" in render_panel(panels[1])
    assert "CUSTOM-001" in render_panel(panels[2])


def test_build_explanation_panel_does_not_mutate_explanation() -> None:
    explanation = create_explanation(evidence_summary={"source_address": "192.0.2.10"})
    original = explanation.to_dict()

    build_explanation_panel(explanation)

    assert explanation.to_dict() == original


def test_cli_helper_has_no_external_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_external_behavior(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Explanation rendering must remain local and side-effect free.")

    monkeypatch.setattr("builtins.open", reject_external_behavior)
    monkeypatch.setattr("pathlib.Path.open", reject_external_behavior)
    monkeypatch.setattr("pathlib.Path.read_text", reject_external_behavior)
    monkeypatch.setattr("pathlib.Path.write_text", reject_external_behavior)
    monkeypatch.setattr("urllib.request.urlopen", reject_external_behavior)
    monkeypatch.setattr(socket, "create_connection", reject_external_behavior)
    monkeypatch.setattr(subprocess, "run", reject_external_behavior)

    panels = build_explanation_panels(
        [create_explanation(evidence_summary={"source_address": "192.0.2.10"})]
    )

    assert len(panels) == 1


def test_cli_helper_does_not_register_commands() -> None:
    assert "app" not in vars(explanation_cli)
    assert "console" not in vars(explanation_cli)
