from __future__ import annotations

from sentinellite.baseline.file_integrity import FileIntegrityBaselineComparison
from sentinellite.models.security_event import SecurityEvent, create_security_event


def file_integrity_baseline_comparison_to_security_event(
    comparison: FileIntegrityBaselineComparison,
) -> SecurityEvent:
    """Normalize a defensive baseline comparison into an informational event."""
    return create_security_event(
        source="file_integrity_baseline",
        event_type="file_integrity_baseline_comparison",
        severity="info",
        message=comparison.message,
        evidence={
            "path": comparison.path,
            "status": comparison.status,
            "changed_fields": list(comparison.changed_fields),
            "baseline_entry": (
                comparison.baseline_entry.to_dict()
                if comparison.baseline_entry is not None
                else None
            ),
            "current_entry": comparison.current_entry.to_dict(),
        },
        raw_data=None,
    )
