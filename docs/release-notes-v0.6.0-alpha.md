# SentinelLite AI v0.6.0-alpha Release Notes

## Release Status

`v0.6.0-alpha` is an in-development alpha milestone until it is formally released. It is intended for controlled demonstration, authorized defensive security learning, and portfolio review. It is not presented as a production EDR release.

## Release Focus

This milestone adds local, read-only history and review commands for SentinelLite JSON alert reports. Existing scan behavior and the v0.5 report schema remain unchanged.

## Added

- A frozen, typed report review model for validated report and alert summaries
- Non-recursive discovery of lowercase JSON report files
- UTF-8, JSON, size, timestamp, report-type, count, and alert-shape validation
- `reports list` for reviewing a local report directory
- `reports show REPORT_PATH` for summarizing one exact local report path
- Clean malformed and incompatible report diagnostics
- Safe literal terminal rendering for report-controlled summary fields
- Automated unit, CLI, and CI smoke coverage for report review

## Changed

- The CLI version display now reports `SentinelLite AI v0.6.0-alpha`.
- The current README and demo flow include local report listing and exact-path review.
- No JSON writer, scan pipeline, detection, configuration, or report-schema behavior changed.

## Validation

- Automated Ruff, Pytest, CLI status, report generation, report listing, exact-path report review, and malformed-report smoke validation is defined for this milestone.
- macOS development validation: pending
- Ubuntu ARM64 validation: pending

## Safety Scope

- Defensive, investigation-focused endpoint observation and local report review only
- Report listing and review are read-only
- No real AI or LLM execution
- No external API or explanation service calls
- No malware classification or confirmed-compromise claims
- No automatic process termination, IP blocking, file repair, deletion, or firewall changes
- No database, persistent report index, dashboard, or monitoring daemon

## Report Review Behavior

`reports list` reads the selected directory non-recursively and displays compatible reports newest first. Directory precedence is:

```text
--report-dir > selected config reporting.output_dir > reports/
```

An existing empty directory succeeds with a clear message. If compatible and invalid JSON candidates are present together, both are displayed with concise diagnostics and the command exits non-zero.

`reports show REPORT_PATH` loads one exact file path. It displays report metadata, stored explanation counts, rule IDs, severity and risk-level counts, and compact alert rows. It does not use list indexes or report IDs as selectors.

Report review does not print evidence, raw JSON, or nested explanation bodies by default. It records only whether a stored explanation object is present and does not regenerate explanations from current rule templates.

## JSON Reporting Compatibility

The JSON writer still produces exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

Optional deterministic explanations remain nested inside individual alerts. Report review reads this existing shape but does not modify reports or add fields.

## Known Limitations

- Report filters are not included in v0.6.
- Report discovery is non-recursive and includes only lowercase `*.json` regular files.
- Report selection for `reports show` requires an exact file path.
- There is no database, persistent index, dashboard, or daemon.
- Config files still require explicit global `--config` selection; automatic discovery is not implemented.
- Real AI-assisted or LLM-based explanation is not implemented.
- macOS development and Ubuntu ARM64 validation remain pending for this milestone.

## Author

Kavisara Samarakoon
