from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

ALLOWED_CONFIDENCE_VALUES = {"low", "medium", "high"}

_REQUIRED_FIELDS = {
    "rule_id",
    "title",
    "summary",
    "why_it_matched",
    "possible_causes",
    "recommended_actions",
    "evidence_summary",
    "confidence",
}


def _string_value(data: Mapping[str, object], field_name: str) -> str:
    value = data[field_name]
    if not isinstance(value, str):
        raise ValueError(  # noqa: TRY004
            f"Alert explanation {field_name} must be a string."
        )
    return value


def _string_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Alert explanation {field_name} must be a list of strings.")
    return list(value)


def _evidence_dict(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(  # noqa: TRY004
            "Alert explanation evidence_summary must be a mapping."
        )

    evidence: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(  # noqa: TRY004
                "Alert explanation evidence_summary keys must be strings."
            )
        evidence[key] = item
    return evidence


@dataclass(frozen=True, slots=True)
class AlertExplanation:
    """Investigation guidance derived only from evidence already provided.

    An explanation must not claim malware detection, invent evidence, or perform
    actions. It records deterministic guidance for a person investigating an alert.
    """

    rule_id: str
    title: str
    summary: str
    why_it_matched: str
    possible_causes: list[str]
    recommended_actions: list[str]
    evidence_summary: dict[str, object]
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "summary": self.summary,
            "why_it_matched": self.why_it_matched,
            "possible_causes": list(self.possible_causes),
            "recommended_actions": list(self.recommended_actions),
            "evidence_summary": dict(self.evidence_summary),
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> AlertExplanation:
        missing_fields = sorted(_REQUIRED_FIELDS.difference(data))
        if missing_fields:
            raise ValueError(
                f"Missing required alert explanation fields: {', '.join(missing_fields)}"
            )

        possible_causes = _string_list(data["possible_causes"], "possible_causes")
        recommended_actions = _string_list(
            data["recommended_actions"], "recommended_actions"
        )
        evidence_summary = _evidence_dict(data["evidence_summary"])

        confidence = _string_value(data, "confidence")
        if confidence not in ALLOWED_CONFIDENCE_VALUES:
            raise ValueError(
                "Alert explanation confidence must be one of: "
                f"{', '.join(sorted(ALLOWED_CONFIDENCE_VALUES))}."
            )

        return cls(
            rule_id=_string_value(data, "rule_id"),
            title=_string_value(data, "title"),
            summary=_string_value(data, "summary"),
            why_it_matched=_string_value(data, "why_it_matched"),
            possible_causes=possible_causes,
            recommended_actions=recommended_actions,
            evidence_summary=evidence_summary,
            confidence=confidence,
        )
