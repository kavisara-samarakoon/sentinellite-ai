# SentinelLite AI Data Contracts

This document describes the schema-v1 alert-report contract implemented for the
`v1.3.0-beta` release candidate (Issue #14, PR #15), and the separate notification summary.
Published `v1.0.0-beta` through `v1.2.0-beta` alert reports use the historical unversioned
contract. Release records remain historical; this document does not claim `v1.3.0-beta` is published.

Both artifact types are local files and may contain or imply operational security data.
They should not be committed or shared casually.

## Alert Report Contract

A newly generated schema-v1 alert report has exactly these six top-level fields:

- `schema_version`
- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

`schema_version` must be the integer `1`, not a boolean, float, string, or null.
There is no top-level `explanations` field. Both default and explained report generation
use this same envelope. The following is a complete, synthetic schema-v1 report:

```json
{
  "schema_version": 1,
  "report_id": "sentinellite-report-2026-01-01T00:00:00+00:00",
  "report_type": "sentinellite_alert_report",
  "generated_at": "2026-01-01T00:00:00+00:00",
  "alert_count": 1,
  "alerts": [
    {
      "alert_id": "synthetic-alert-001",
      "rule_id": "AUTH-001",
      "rule_name": "Failed SSH Login",
      "category": "authentication",
      "severity": "medium",
      "base_score": 50,
      "risk_score": 50,
      "risk_level": "medium",
      "event_id": "synthetic-event-001",
      "event_type": "ssh_failed_login",
      "source": "sshd",
      "message": "Synthetic failed SSH authentication attempt",
      "description": "A synthetic authentication rule match.",
      "recommendation": "Review the synthetic evidence.",
      "evidence": {"synthetic": true}
    }
  ]
}
```

Every alert must contain all 15 fields shown above. Unknown report or alert fields are
incompatible; only the optional `explanation` field may be added to an alert. Identifiers
`report_id`, `alert_id`, `rule_id`, and `event_id` must be non-empty strings. Other alert
text fields must be strings and may be empty. `base_score` and `risk_score` must be integers
from 0 through 100, never booleans. Severity and risk level must each be one of `info`,
`low`, `medium`, `high`, or `critical`. Stored scores and levels are validated independently;
review and export do not recompute them from default thresholds. `evidence` must be an
object containing JSON-native values.

`alert_count` must be a non-negative integer equal to the number of entries in `alerts`.
An empty alert array is valid. `report_type` must be `sentinellite_alert_report`, and
`generated_at` must be a timezone-aware ISO datetime.

### Legacy-unversioned compatibility

A complete historical report has exactly the five envelope fields `report_id`,
`report_type`, `generated_at`, `alert_count`, and `alerts`, with no `schema_version` field.
It requires the same complete 15-field alerts and, when present, complete explanations.
The canonical parser identifies it as `legacy-unversioned`; reading or exporting it does
not add a version or modify its source file. Abbreviated or manually edited objects are
not accepted merely because they omit `schema_version`.

A positive integer version greater than `1` is unsupported. A present but invalid version
is incompatible and never falls back to legacy interpretation. Future report bodies are
not projected under schema-v1 rules.

Stored-report review, dashboard, and notification-export inputs use `parse_report_json()` from
[`reporting/validation.py`](../src/sentinellite/reporting/validation.py). It rejects invalid
UTF-8, JSON syntax errors, duplicate keys at every depth, non-finite numbers, and numeric
overflow as malformed. Decoded reports with missing, incorrectly typed, or unknown fields,
invalid Unicode scalars, invalid timestamps, count mismatches, or incomplete alerts or
explanations are incompatible. A report must validate completely before any summary is
projected; limiting the display does not bypass validation of hidden alerts.

### Optional per-alert explanation

When `--include-explanations` is passed, or an explicitly selected TOML config enables
`reporting.include_explanations`, each generated alert receives a nested `explanation`
object. The six top-level schema-v1 fields do not change. By default, stored alerts have
no `explanation`, even though the scan CLI can display deterministic explanation panels.
For an alert with `rule_id` equal to `AUTH-001`, the optional object can be:

```json
{
  "rule_id": "AUTH-001",
  "title": "Failed SSH Login Attempt",
  "summary": "A synthetic authentication event matched the rule.",
  "why_it_matched": "The event type is ssh_failed_login.",
  "possible_causes": ["A deliberately constructed fixture event"],
  "recommended_actions": ["Review the synthetic evidence"],
  "evidence_summary": {"synthetic": true},
  "confidence": "medium"
}
```

All eight fields are required and no additional explanation fields are accepted.
`rule_id` must match the parent alert. Title, summary, and match reason are strings;
causes and actions are arrays of strings; evidence summary is an object; confidence is
`low`, `medium`, or `high`. Explanations are generated by local deterministic templates.
They do not involve AI, an LLM, or an external service.

### Stored-report review and dashboard

`sentinellite reports list --report-dir reports` reads regular lowercase `.json` files
directly in the selected directory, ignoring symlinks and subdirectories. It labels valid
schema-v1 reports `valid (v1)`, valid historical reports `valid (legacy)`, future schemas
`unsupported`, and malformed or incompatible inputs `invalid`. Invalid entries have no
partial report metadata. Malformed, incompatible, and unsupported diagnostics are distinct.
The command lists valid reports alongside invalid entries and exits with code 1 if any
candidate fails; an empty directory exits successfully. A missing review directory is an error.

`sentinellite reports show REPORT_PATH` displays `Report contract` as `schema-v1` or
`legacy-unversioned`, with `Schema version` equal to `1` or `unversioned`. It shows stored
alerts and explanation presence, omits evidence and explanation bodies, and exits with
code 1 on malformed, incompatible, unsupported, unreadable, or oversized reports.

`sentinellite dashboard export --reports-dir reports --output reports/dashboard.html --limit 25`
uses only completely validated schema-v1 or legacy reports. Invalid, unsupported, unreadable,
and oversized report candidates are skipped and included in `Skipped files`; symlinks and
subdirectories are excluded from discovery. The 2 MiB limit applies to each input file.
All valid reports count toward the loaded total. At most `--limit` newest reports and
`--limit` alerts from those selected reports are shown, with stable ordering for ties.
Supported alerts have no separate timestamp field, so their display time uses report time.
HTML escapes summary fields and omits raw evidence. A missing or empty input directory
produces an empty dashboard. The output remains static, offline HTML with embedded CSS:
no server, network requests, external scripts, live monitoring, or automatic remediation.

Review, dashboard, and notification export use stored values without rerunning collection,
detection, risk scoring, or explanation generation. Reports and summary text remain sensitive.

## Notification Summary Contract

A notification summary is a separate artifact, not an alert report. Its top-level fields
are exactly:

- `schema_version`
- `output_type`
- `source`
- `alert_count`
- `included_alert_count`
- `omitted_alert_count`
- `severity_counts`
- `risk_level_counts`
- `alerts`

`schema_version` remains the integer `1`, and `output_type` is
`sentinellite_notification_summary`.

```json
{
  "schema_version": 1,
  "output_type": "sentinellite_notification_summary",
  "source": {
    "report_id": "sentinellite-report-2026-01-01T00:00:00+00:00",
    "generated_at": "2026-01-01T00:00:00+00:00"
  },
  "alert_count": 1,
  "included_alert_count": 1,
  "omitted_alert_count": 0,
  "severity_counts": {"medium": 1},
  "risk_level_counts": {"medium": 1},
  "alerts": [
    {
      "rule_id": "AUTH-001",
      "category": "authentication",
      "severity": "medium",
      "risk_score": 50,
      "risk_level": "medium"
    }
  ]
}
```

At most 20 alerts are included. Alerts are ordered by descending stored risk score with
stable ordering for ties. `omitted_alert_count` records alerts beyond that limit. Export
uses stored values and does not rerun collection, detection, scoring, or explanations.

The privacy-minimized summary excludes:

- messages, descriptions, recommendations, and evidence
- explanation bodies and investigation actions
- usernames, addresses, paths, process details, command lines, and hashes
- the source report path and raw source JSON

Privacy-minimized does not mean anonymous or non-sensitive. Rule IDs, categories, timing,
severity, and risk information can still disclose operational context.

## Source Preservation and Separation

`reports export-notification` requires an exact compatible source report and an explicit
output path. It refuses an existing output and refuses to use the source report as the
output. A successful export does not modify the source report.

Keep the artifacts in separate directories. `reports list` treats lowercase `.json` files
in its selected directory as alert-report candidates, so a notification summary placed
there is intentionally reported as incompatible.

Notification export writes local JSON only. It does not send data, make network requests,
or provide email, Slack, Discord, webhook, SMS, provider, token, AI, or LLM behavior.

## Contract Compatibility Rule

New alert reports use schema v1; complete historical unversioned reports remain readable
under their original contract. Notification summaries retain their separate schema.
Future contract changes require explicit versioning, compatibility tests, documentation,
and release review; consumers must not infer support for an unknown version.
