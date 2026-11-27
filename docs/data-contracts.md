# SentinelLite AI Data Contracts

This document describes the schema-v1 alert-report contract in the published `v1.3.0-beta`
GitHub pre-release and the separate notification summary contract.
Published `v1.0.0-beta` through `v1.2.0-beta` alert reports use the historical unversioned
contract. See the [v1.3.0-beta release notes](release-notes-v1.3.0-beta.md) for publication details.

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

## Offline Telemetry Contract (`sentinellite_telemetry` v1)

`sentinellite reports export-telemetry REPORT_PATH --output OUTPUT_PATH` writes an
offline, privacy-minimized telemetry JSON file derived from one explicitly selected alert
report. It performs no network activity, credential acquisition, or Azure ingestion.

### Envelope & Group Fields

- **Top-level fields (exact allowlist):** `schema_version` (integer `1`, never `bool`),
  `output_type` (`"sentinellite_telemetry"`), `export_id` (generated lowercase UUIDv4),
  `exported_at` (generated canonical UTC ISO-8601 `Z` timestamp), `alert_count`
  (`0 <= alert_count <= 1000`), and `groups` (list of `0..128` groups).
- **Group fields (exact allowlist):** `rule_id` (closed v1 allowlist: `AUTH-001`–`AUTH-003`,
  `PROC-001`–`PROC-003`, `NET-001`–`NET-003`, `FIM-001`–`FIM-008`), `severity`,
  `risk_level`, and `count` (positive exact integer). Groups are unique and sorted
  lexicographically by `(rule_id, severity, risk_level)` with `sum(count) == alert_count`.
- **Empty reports:** `alert_count: 0` with `groups: []` is valid.
- **Excluded source data:** Report IDs, timestamps, alert/event IDs, paths, usernames,
  hostnames, IP/MAC addresses, process arguments, hashes, messages, descriptions,
  recommendations, explanations, arbitrary categories, numeric risk scores, and raw
  evidence are never projected.

### Resource Limits, Filesystem Policy, & Saved-Artifact Validation

- **Fail-closed limits:** `1` report per export, `2,097,152` bytes (2 MiB) max input, `64`
  max JSON container nesting depth, `1,000` max alerts, `128` max groups, `65,536` bytes
  (64 KiB) max serialized output and max saved-telemetry input.
- **Private directory & source policy:** Both source and output parent directories must
  already exist, be owned by the effective user, have mode `0700`, and not be symlinks.
  Source reports must be owner-owned regular files with no group/other permission bits
  (mode `0600` recommended). Existing source reports are never modified or `chmod`ed. POSIX
  mode checks assume trusted ancestor directories, trusted ACL configurations, and trusted
  filesystems; unsupported required safety primitives fail closed.
- **Writer validation & no-clobber publication:** `write_telemetry_file()` strictly
  validates and canonically serializes the payload before any filesystem mutation, writes
  complete bytes to a `0600` same-directory temporary file, `fsync`s, publishes via atomic
  no-clobber `os.link`, and unlinks the temporary file without modifying the source report.
  Pre-publication cleanup failures are reported explicitly without losing the original error
  (`published=False`); post-publication cleanup/sync failures report `published=True`
  without deleting the published file. Ancestor-directory symlinks and concurrent
  equivalent-privilege modification remain OS-level residual risks.
- **Saved-artifact validation:** `parse_telemetry_json()` validates bounded UTF-8 telemetry
  JSON, rejects duplicate keys, nonfinite numbers, lone surrogates, and unsorted/duplicate
  groups, and preserves `export_id` and `exported_at`.
- **Outcomes & guarantees:** Errors report fixed sanitized outcomes (`malformed`,
  `incompatible`, `unsupported-schema`, `unsupported-rule`, `limit-exceeded`,
  `output-error`). Minimization is not anonymization, structural validation is not
  authenticity, and exactly-once delivery across re-exports is not guaranteed.

## Contract Compatibility Rule

New alert reports use schema v1; complete historical unversioned reports remain readable
under their original contract. Notification summaries retain their separate schema.
Future contract changes require explicit versioning, compatibility tests, documentation,
and release review; consumers must not infer support for an unknown version.
