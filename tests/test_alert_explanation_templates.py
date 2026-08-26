import subprocess

import pytest

from sentinellite.explanations import AlertExplanation
from sentinellite.explanations.templates import (
    EXPLANATION_TEMPLATES,
    AlertExplanationTemplate,
    build_generic_explanation,
    get_explanation_template,
)

EXPECTED_RULE_IDS = {
    "AUTH-001",
    "AUTH-002",
    "AUTH-003",
    "PROC-001",
    "PROC-002",
    "PROC-003",
    "NET-001",
    "NET-002",
    "NET-003",
    "FIM-001",
    "FIM-002",
    "FIM-003",
    "FIM-004",
    "FIM-005",
    "FIM-006",
    "FIM-007",
    "FIM-008",
}


def template_wording(template: AlertExplanationTemplate) -> str:
    return " ".join(
        [
            template.title,
            template.summary,
            template.why_it_matched_template,
            *template.possible_causes,
            *template.recommended_actions,
        ]
    ).lower()


def test_all_existing_rule_ids_have_explanation_templates() -> None:
    assert set(EXPLANATION_TEMPLATES) == EXPECTED_RULE_IDS
    assert all(key == template.rule_id for key, template in EXPLANATION_TEMPLATES.items())


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULE_IDS))
def test_get_explanation_template_returns_correct_template(rule_id: str) -> None:
    assert get_explanation_template(rule_id) is EXPLANATION_TEMPLATES[rule_id]


def test_get_explanation_template_returns_none_for_unknown_rule() -> None:
    assert get_explanation_template("UNKNOWN-999") is None


def test_template_to_explanation_returns_alert_explanation() -> None:
    template = EXPLANATION_TEMPLATES["PROC-001"]

    explanation = template.to_explanation({"exe": "/tmp/example"})

    assert isinstance(explanation, AlertExplanation)
    assert explanation.rule_id == template.rule_id
    assert explanation.title == template.title
    assert explanation.summary == template.summary
    assert explanation.why_it_matched == template.why_it_matched_template
    assert explanation.confidence == template.confidence


def test_template_to_explanation_copies_mutable_values() -> None:
    template = EXPLANATION_TEMPLATES["FIM-004"]
    evidence_summary = {"path": "/selected/config.txt", "status": "changed"}

    explanation = template.to_explanation(evidence_summary)

    assert explanation.possible_causes == template.possible_causes
    assert explanation.possible_causes is not template.possible_causes
    assert explanation.recommended_actions == template.recommended_actions
    assert explanation.recommended_actions is not template.recommended_actions
    assert explanation.evidence_summary == evidence_summary
    assert explanation.evidence_summary is not evidence_summary


def test_fim_004_explanation_uses_baseline_change_investigation_wording() -> None:
    explanation = EXPLANATION_TEMPLATES["FIM-004"].to_explanation()
    wording = " ".join(
        [
            explanation.title,
            explanation.summary,
            explanation.why_it_matched,
            *explanation.recommended_actions,
        ]
    ).lower()

    assert "baseline" in wording
    assert "change" in wording
    assert "confirm" in wording
    assert "review" in wording


def test_auth_001_explanation_uses_failed_login_investigation_wording() -> None:
    explanation = EXPLANATION_TEMPLATES["AUTH-001"].to_explanation()
    wording = " ".join(
        [
            explanation.title,
            explanation.summary,
            explanation.why_it_matched,
            *explanation.recommended_actions,
        ]
    ).lower()

    assert "failed ssh login" in wording
    assert "review" in wording
    assert "repeated" in wording
    assert "username" in wording


def test_generic_explanation_is_low_confidence_and_copies_evidence() -> None:
    evidence_summary = {"observed_value": "provided by caller"}

    explanation = build_generic_explanation("CUSTOM-001", evidence_summary)

    assert explanation.rule_id == "CUSTOM-001"
    assert explanation.title == "General Alert Explanation"
    assert explanation.confidence == "low"
    assert explanation.evidence_summary == evidence_summary
    assert explanation.evidence_summary is not evidence_summary


def test_generic_explanation_does_not_invent_rule_specific_details() -> None:
    explanation = build_generic_explanation("CUSTOM-001")

    assert explanation.summary == "No specific deterministic template exists for this rule."
    assert explanation.possible_causes == []
    assert explanation.recommended_actions == [
        "review the rule match",
        "review the supplied evidence",
        "inspect related logs",
        "consider the wider system context",
    ]


def test_template_wording_does_not_claim_malware_detection() -> None:
    assert all(
        "malware" not in template_wording(template) for template in EXPLANATION_TEMPLATES.values()
    )


def test_template_wording_does_not_claim_compromise() -> None:
    assert all(
        "compromise" not in template_wording(template)
        for template in EXPLANATION_TEMPLATES.values()
    )


def test_templates_have_no_external_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_external_behavior(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Explanation templates must remain pure data.")

    monkeypatch.setattr("builtins.open", reject_external_behavior)
    monkeypatch.setattr("urllib.request.urlopen", reject_external_behavior)
    monkeypatch.setattr(subprocess, "run", reject_external_behavior)

    explanation = EXPLANATION_TEMPLATES["NET-001"].to_explanation({"local_port": 8080})
    fallback = build_generic_explanation("UNKNOWN-001", {"source": "caller"})

    assert explanation.evidence_summary == {"local_port": 8080}
    assert fallback.evidence_summary == {"source": "caller"}
