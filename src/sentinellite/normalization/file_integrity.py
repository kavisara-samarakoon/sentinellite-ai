from __future__ import annotations

from sentinellite.collectors.file_integrity import FileIntegrityRecord
from sentinellite.models.security_event import SecurityEvent, create_security_event


def _create_observation_message(record: FileIntegrityRecord) -> str:
    known_missing_path = (
        not record.exists
        and record.error is not None
        and "does not exist" in record.error.lower()
    )

    if record.error is not None and not known_missing_path:
        return f"File integrity check had an error for {record.path}: {record.error}"

    if not record.exists:
        return f"Observed missing file at {record.path}"

    if not record.is_file:
        return f"Observed directory path during file integrity check: {record.path}"

    return f"Observed file integrity state for {record.path}"


def file_integrity_record_to_security_event(record: FileIntegrityRecord) -> SecurityEvent:
    """Convert collected file integrity facts into an informational security event."""
    return create_security_event(
        source="file_integrity",
        event_type="file_integrity_observation",
        severity="info",
        message=_create_observation_message(record),
        evidence={
            "path": record.path,
            "exists": record.exists,
            "is_file": record.is_file,
            "size_bytes": record.size_bytes,
            "modified_time_epoch": record.modified_time_epoch,
            "sha256": record.sha256,
            "error": record.error,
        },
        raw_data=None,
    )
