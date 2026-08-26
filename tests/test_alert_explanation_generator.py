import socket
import subprocess

import pytest

from sentinellite.explanations import (
    EXPLANATION_TEMPLATES,
    AlertExplanation,
    explanation_to_dict,
    explanations_to_dicts,
    generate_alert_explanation,
    generate_alert_explanations,
)


def test_generate_known_rule_returns_template_based_explanation() -> None:
    explanation = generate_alert_explanation("AUTH-001")
    template = EXPLANATION_TEMPLATES["AUTH-001"]

    assert isinstance(explanation, AlertExplanation)
    assert explanation.rule_id == template.rule_id
    assert explanation.title == template.title
    assert explanation.summary == template.summary
    assert explanation.why_it_matched == template.why_it_matched_template
    assert explanation.confidence == template.confidence


def test_generate_unknown_rule_returns_generic_low_confidence_explanation() -> None:
    explanation = generate_alert_explanation("CUSTOM-001")

    assert explanation.rule_id == "CUSTOM-001"
    assert explanation.title == "General Alert Explanation"
    assert explanation.summary == "No specific deterministic template exists for this rule."
    assert explanation.confidence == "low"


def test_generate_alert_explanation_preserves_and_copies_evidence() -> None:
    evidence_summary = {
        "source_address": "192.0.2.10",
        "attempt_count": 3,
    }
    original_evidence = dict(evidence_summary)

    explanation = generate_alert_explanation("AUTH-001", evidence_summary)

    assert explanation.evidence_summary == original_evidence
    assert explanation.evidence_summary is not evidence_summary
    assert evidence_summary == original_evidence


def test_generate_alert_explanations_preserves_order_for_mixed_rules() -> None:
    alert_items = [
        {"rule_id": "FIM-004", "evidence_summary": {"status": "changed"}},
        {"rule_id": "CUSTOM-001", "evidence_summary": {"source": "caller"}},
        {"rule_id": "NET-001", "evidence_summary": {"local_port": 8080}},
    ]

    explanations = generate_alert_explanations(alert_items)

    assert [explanation.rule_id for explanation in explanations] == [
        "FIM-004",
        "CUSTOM-001",
        "NET-001",
    ]
    assert explanations[0].title == EXPLANATION_TEMPLATES["FIM-004"].title
    assert explanations[1].title == "General Alert Explanation"
    assert explanations[1].confidence == "low"
    assert explanations[2].title == EXPLANATION_TEMPLATES["NET-001"].title


def test_generate_alert_explanations_does_not_mutate_input_evidence() -> None:
    evidence_summary = {"path": "/selected/config.txt", "status": "changed"}
    alert_items = [{"rule_id": "FIM-004", "evidence_summary": evidence_summary}]

    explanations = generate_alert_explanations(alert_items)

    assert explanations[0].evidence_summary == evidence_summary
    assert explanations[0].evidence_summary is not evidence_summary
    assert evidence_summary == {
        "path": "/selected/config.txt",
        "status": "changed",
    }


def test_generate_alert_explanations_rejects_missing_rule_id() -> None:
    with pytest.raises(ValueError, match="missing required field: rule_id"):
        generate_alert_explanations([{"evidence_summary": {}}])


@pytest.mark.parametrize("invalid_rule_id", [None, 7, [], {}])
def test_generate_alert_explanations_rejects_non_string_rule_id(
    invalid_rule_id: object,
) -> None:
    with pytest.raises(ValueError, match="rule_id must be a string"):
        generate_alert_explanations([{"rule_id": invalid_rule_id}])


@pytest.mark.parametrize(
    "invalid_evidence_summary",
    [None, "not-a-mapping", [], 7],
)
def test_generate_alert_explanations_rejects_invalid_evidence_summary(
    invalid_evidence_summary: object,
) -> None:
    with pytest.raises(ValueError, match="evidence_summary must be a mapping"):
        generate_alert_explanations(
            [
                {
                    "rule_id": "AUTH-001",
                    "evidence_summary": invalid_evidence_summary,
                }
            ]
        )


def test_explanation_to_dict_returns_expected_dictionary() -> None:
    explanation = generate_alert_explanation(
        "AUTH-001",
        {"source_address": "192.0.2.10"},
    )

    result = explanation_to_dict(explanation)

    assert result == explanation.to_dict()
    assert result["rule_id"] == "AUTH-001"
    assert result["evidence_summary"] == {"source_address": "192.0.2.10"}


def test_explanations_to_dicts_preserves_order() -> None:
    explanations = [
        generate_alert_explanation("AUTH-001"),
        generate_alert_explanation("CUSTOM-001"),
        generate_alert_explanation("FIM-004"),
    ]

    serialized = explanations_to_dicts(explanations)

    assert [item["rule_id"] for item in serialized] == [
        "AUTH-001",
        "CUSTOM-001",
        "FIM-004",
    ]


def test_generator_has_no_external_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_external_behavior(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Alert explanation generation must remain local and side-effect free.")

    monkeypatch.setattr("builtins.open", reject_external_behavior)
    monkeypatch.setattr("pathlib.Path.open", reject_external_behavior)
    monkeypatch.setattr("pathlib.Path.read_text", reject_external_behavior)
    monkeypatch.setattr("pathlib.Path.write_text", reject_external_behavior)
    monkeypatch.setattr("urllib.request.urlopen", reject_external_behavior)
    monkeypatch.setattr(socket, "create_connection", reject_external_behavior)
    monkeypatch.setattr(subprocess, "run", reject_external_behavior)

    explanations = generate_alert_explanations(
        [
            {"rule_id": "AUTH-001", "evidence_summary": {"attempt_count": 2}},
            {"rule_id": "CUSTOM-001", "evidence_summary": {"source": "caller"}},
        ]
    )

    assert [explanation.rule_id for explanation in explanations] == [
        "AUTH-001",
        "CUSTOM-001",
    ]
