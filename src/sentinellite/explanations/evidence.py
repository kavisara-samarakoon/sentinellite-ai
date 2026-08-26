from collections.abc import Mapping


def _alert_value(alert: object, field_name: str) -> object | None:
    if isinstance(alert, Mapping):
        return alert.get(field_name)
    return getattr(alert, field_name, None)


def build_alert_evidence_summary(alert: object) -> dict[str, object]:
    """Return a deterministic summary containing only existing alert evidence."""
    evidence_summary: dict[str, object] = {}

    for output_name, field_name in (
        ("rule_id", "rule_id"),
        ("severity", "severity"),
        ("score", "risk_score"),
        ("event_type", "event_type"),
        ("source", "source"),
        ("message", "message"),
    ):
        value = _alert_value(alert, field_name)
        if value is not None:
            evidence_summary[output_name] = value

    alert_evidence = _alert_value(alert, "evidence")
    if isinstance(alert_evidence, Mapping):
        for field_name in ("path", "status"):
            value = alert_evidence.get(field_name)
            if value is not None:
                evidence_summary[field_name] = value

    return evidence_summary
