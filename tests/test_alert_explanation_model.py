import pytest

from sentinellite.explanations import ALLOWED_CONFIDENCE_VALUES, AlertExplanation


def create_explanation_data(confidence: str = "medium") -> dict[str, object]:
    return {
        "rule_id": "file_integrity_changed",
        "title": "Observed file differs from baseline",
        "summary": "A monitored file has changed since the authorized baseline.",
        "why_it_matched": "The current SHA-256 value differs from the baseline value.",
        "possible_causes": [
            "An authorized configuration update",
            "An unexpected file modification",
        ],
        "recommended_actions": [
            "Confirm whether the change was authorized",
            "Review the recorded file metadata",
        ],
        "evidence_summary": {
            "path": "/selected/config.txt",
            "changed_fields": ["sha256"],
        },
        "confidence": confidence,
    }


def test_alert_explanation_to_dict_from_dict_round_trip_preserves_all_fields() -> None:
    data = create_explanation_data()

    explanation = AlertExplanation.from_dict(data)

    assert explanation.to_dict() == data
    assert AlertExplanation.from_dict(explanation.to_dict()) == explanation


def test_alert_explanation_from_dict_copies_mutable_fields() -> None:
    data = create_explanation_data()
    possible_causes = data["possible_causes"]
    recommended_actions = data["recommended_actions"]
    evidence_summary = data["evidence_summary"]

    explanation = AlertExplanation.from_dict(data)

    assert explanation.possible_causes == possible_causes
    assert explanation.possible_causes is not possible_causes
    assert explanation.recommended_actions == recommended_actions
    assert explanation.recommended_actions is not recommended_actions
    assert explanation.evidence_summary == evidence_summary
    assert explanation.evidence_summary is not evidence_summary


def test_alert_explanation_to_dict_copies_mutable_fields() -> None:
    explanation = AlertExplanation.from_dict(create_explanation_data())

    serialized = explanation.to_dict()

    assert serialized["possible_causes"] is not explanation.possible_causes
    assert serialized["recommended_actions"] is not explanation.recommended_actions
    assert serialized["evidence_summary"] is not explanation.evidence_summary


@pytest.mark.parametrize("confidence", sorted(ALLOWED_CONFIDENCE_VALUES))
def test_alert_explanation_accepts_valid_confidence_values(confidence: str) -> None:
    explanation = AlertExplanation.from_dict(create_explanation_data(confidence))

    assert explanation.confidence == confidence


def test_alert_explanation_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError, match="confidence must be one of"):
        AlertExplanation.from_dict(create_explanation_data("certain"))


@pytest.mark.parametrize(
    "missing_field",
    [
        "rule_id",
        "title",
        "summary",
        "why_it_matched",
        "possible_causes",
        "recommended_actions",
        "evidence_summary",
        "confidence",
    ],
)
def test_alert_explanation_rejects_missing_required_fields(missing_field: str) -> None:
    data = create_explanation_data()
    del data[missing_field]

    with pytest.raises(ValueError, match="Missing required alert explanation fields"):
        AlertExplanation.from_dict(data)


@pytest.mark.parametrize(
    "invalid_possible_causes",
    [None, {}, "not-a-list", ["valid cause", 7]],
)
def test_alert_explanation_rejects_invalid_possible_causes(
    invalid_possible_causes: object,
) -> None:
    data = create_explanation_data()
    data["possible_causes"] = invalid_possible_causes

    with pytest.raises(ValueError, match="possible_causes must be a list of strings"):
        AlertExplanation.from_dict(data)


@pytest.mark.parametrize(
    "invalid_recommended_actions",
    [None, {}, "not-a-list", ["valid action", 7]],
)
def test_alert_explanation_rejects_invalid_recommended_actions(
    invalid_recommended_actions: object,
) -> None:
    data = create_explanation_data()
    data["recommended_actions"] = invalid_recommended_actions

    with pytest.raises(ValueError, match="recommended_actions must be a list of strings"):
        AlertExplanation.from_dict(data)


@pytest.mark.parametrize("invalid_evidence_summary", [None, [], "not-a-mapping"])
def test_alert_explanation_rejects_invalid_evidence_summary(
    invalid_evidence_summary: object,
) -> None:
    data = create_explanation_data()
    data["evidence_summary"] = invalid_evidence_summary

    with pytest.raises(ValueError, match="evidence_summary must be a mapping"):
        AlertExplanation.from_dict(data)


def test_alert_explanation_model_has_no_llm_or_api_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_external_behavior(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("The alert explanation model must remain pure data.")

    monkeypatch.setattr("builtins.open", reject_external_behavior)
    monkeypatch.setattr("urllib.request.urlopen", reject_external_behavior)

    explanation = AlertExplanation.from_dict(create_explanation_data())

    assert explanation.rule_id == "file_integrity_changed"
