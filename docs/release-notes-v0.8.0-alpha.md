# SentinelLite AI v0.8.0-alpha Release Notes

## Release Status

`v0.8.0-alpha` is a published GitHub pre-release alpha milestone. It is intended for controlled demonstration, authorized defensive security learning, and portfolio review. It is not presented as a production EDR release.

## Release Focus

This milestone adds local, privacy-minimized notification summary export from an explicitly selected existing SentinelLite alert report. The exporter prepares a separate JSON artifact and does not deliver it externally.

## Added

- Versioned notification summary contract with a distinct output type
- Deterministic summary builder using stored `ReviewedReport` data only
- Privacy-minimized severity, risk-level, and per-alert summary fields
- Safe local JSON writer with exclusive creation and overwrite refusal
- Owner-only `0600` output permissions on POSIX systems where supported
- `reports export-notification REPORT_PATH --output OUTPUT_PATH`
- Integration and privacy regression coverage
- Source-report preservation and report review compatibility coverage
- Lightweight CI smoke validation for local notification export

## Changed

- The CLI version display now reports `SentinelLite AI v0.8.0-alpha`.
- The README, demo guide, security guidance, and generated-artifact ignore rules now cover notification summaries.
- `notifications/` is the recommended project-local output location.
- No detection rule, risk score, scan pipeline, configuration behavior, dependency, explanation behavior, or existing alert-report writer changed.

## Validation

- GitHub PR #7 CI passed for both `push` and `pull_request` workflows.
- macOS development validation: passed
- Ubuntu ARM64 validation: passed on Linux `aarch64` with Python 3.14.4
- Ruff passed, and Pytest passed with 568 tests.
- The CLI displayed `SentinelLite AI v0.8.0-alpha`.
- The Ubuntu/Debian-style fixture scan produced 3 authentication events and 3 alerts.
- Notification export produced 3 included alerts and 0 omitted alerts.
- Notification JSON schema and privacy compatibility validation passed. The exported JSON did not contain `labadmin`, `demo-user`, `192.0.2.10`, `192.0.2.11`, `/usr/bin/id`, `Failed SSH login attempt`, or `Successful SSH login`.
- The source alert report retained exactly the five established top-level fields: `report_id`, `report_type`, `generated_at`, `alert_count`, and `alerts`. No top-level `explanations` field was added.
- Report review accepted the original generated alert report after notification export.
- The Ubuntu worktree was clean after validation.
- Published as a GitHub pre-release.

## Safety Scope

- Defensive, investigation-focused endpoint observation only
- Local notification summary export only
- Explicit existing source report selection only
- No external delivery or network traffic
- No real AI or LLM execution
- No external API calls
- No malware classification or confirmed-compromise claims
- No production EDR claim
- No automatic remediation, process termination, IP blocking, file deletion or repair, permission modification, or firewall changes
- No database, daemon, background monitoring, or dashboard change
- No notification configuration behavior
- No existing alert-report schema change

## Notification Export Behavior

The command requires an exact compatible SentinelLite alert report and an explicit output path:

```text
reports export-notification REPORT_PATH --output OUTPUT_PATH
```

The output parent directory must already exist, and the output file must not already exist. The exporter reads stored reviewed report data only. It does not collect events, run detection, rescore alerts, regenerate explanations, inspect explanation templates, change the source report, or send anything externally.

Notification summaries should normally be stored in `notifications/`, not `reports/`. Report discovery treats lowercase `.json` files as alert-report candidates, and the notification schema is intentionally incompatible with the alert-report schema.

## Notification JSON Compatibility

Notification JSON is a separate, versioned schema with these top-level fields:

- `schema_version`
- `output_type`
- `source`
- `alert_count`
- `included_alert_count`
- `omitted_alert_count`
- `severity_counts`
- `risk_level_counts`
- `alerts`

The source object contains only `report_id` and `generated_at`. Each included alert contains only `rule_id`, `category`, `severity`, stored `risk_score`, and stored `risk_level`. At most 20 alerts are included, ordered by descending stored risk score with original report order preserved for ties.

The notification artifact excludes alert messages, evidence, explanation bodies, recommendations, usernames, IP addresses, file paths, process names, command lines, hashes, and raw source report JSON. Privacy minimization reduces exposure but does not make the artifact non-sensitive.

## Existing Report JSON Compatibility

The established SentinelLite alert-report JSON schema remains unchanged and separate. Alert reports retain exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

Notification data is not embedded in alert reports, no top-level `explanations` field is added, and exporting a notification summary leaves the source report byte-for-byte unchanged.

## Known Limitations

- Email, Slack, Discord, webhook, and SMS sending are not implemented.
- Provider integrations are not implemented.
- Background monitoring and a daemon are not implemented.
- Notification configuration is not implemented.
- Notification output is JSON only.
- The output parent directory must already exist.
- The output file must not already exist.
- Notification summaries should not be placed in `reports/`.
- Privacy-minimized summaries remain sensitive operational artifacts.
- Real AI-assisted or LLM-based explanation is not implemented.

## Author

Kavisara Samarakoon
