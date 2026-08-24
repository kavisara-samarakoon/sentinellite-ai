from collections.abc import Iterable, Mapping

from sentinellite.explanations.models import AlertExplanation
from sentinellite.explanations.templates import (
    build_generic_explanation,
    get_explanation_template,
)


def generate_alert_explanation(
    rule_id: str,
    evidence_summary: Mapping[str, object] | None = None,
) -> AlertExplanation:
    """Build local, deterministic guidance for one rule match."""
    template = get_explanation_template(rule_id)
    if template is None:
        return build_generic_explanation(rule_id, evidence_summary)
    return template.to_explanation(evidence_summary)


def generate_alert_explanations(
    alert_items: Iterable[Mapping[str, object]],
) -> list[AlertExplanation]:
    """Build one explanation per alert item while preserving input order."""
    explanations: list[AlertExplanation] = []

    for item in alert_items:
        if not isinstance(item, Mapping):
            raise ValueError("Each alert item must be a mapping.")  # noqa: TRY004
        if "rule_id" not in item:
            raise ValueError("Alert item is missing required field: rule_id.")

        rule_id = item["rule_id"]
        if not isinstance(rule_id, str):
            raise ValueError("Alert item rule_id must be a string.")  # noqa: TRY004

        evidence_summary: Mapping[str, object] | None = None
        if "evidence_summary" in item:
            evidence_value = item["evidence_summary"]
            if not isinstance(evidence_value, Mapping):
                raise ValueError("Alert item evidence_summary must be a mapping.")
            evidence_summary = evidence_value

        explanations.append(generate_alert_explanation(rule_id, evidence_summary))

    return explanations


def explanation_to_dict(explanation: AlertExplanation) -> dict[str, object]:
    """Serialize one explanation for a future reporting boundary."""
    return explanation.to_dict()


def explanations_to_dicts(
    explanations: Iterable[AlertExplanation],
) -> list[dict[str, object]]:
    """Serialize explanations while preserving their input order."""
    return [explanation_to_dict(explanation) for explanation in explanations]
