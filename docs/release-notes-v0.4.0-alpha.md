# SentinelLite AI v0.4.0-alpha Release Notes

## Release Status

`v0.4.0-alpha` is an in-development alpha milestone until it is formally released. It is intended for controlled demonstration, authorized defensive security learning, and portfolio review rather than production deployment.

## Release Focus

This milestone adds optional deterministic explanation export inside JSON alert reports. Users must explicitly pass `--include-explanations`; default JSON reports remain unchanged.

Terminal explanation panels continue to appear when scored alerts exist. Real AI or LLM integration is not implemented.

## Added

- Optional JSON explanation export through `--include-explanations` for:
  - `scan-auth`
  - `scan-process`
  - `scan-network`
  - `scan-files`
  - `scan-files-baseline`
- One deterministic, investigation-focused `explanation` object nested inside each alert when requested
- Shared evidence-summary extraction using only existing scored alert fields
- Backward-compatibility tests for default reports
- CLI and pipeline tests covering default, opt-in, and empty reports
- CI smoke validation for nested JSON explanation objects

## Validation

- Ruff: passed
- Pytest: 308 tests passed on macOS development validation
- Ubuntu ARM64 validation: passed

Ubuntu ARM64 validation passed on an Ubuntu ARM64 VM using Python 3.14.4. Ruff passed, Pytest passed with 308 tests, the CLI displayed `SentinelLite AI v0.4.0-alpha`, the default authentication scan kept legacy JSON output, and the `--include-explanations` authentication scan wrote nested explanation objects for all four alerts while preserving the same five top-level report fields.
## Safety Scope

- Deterministic, local, rule-based guidance only
- Investigation prompts rather than conclusions
- Evidence derived only from existing scored alert data
- No real AI or LLM execution
- No external API or explanation service calls
- No malware detection claim
- No confirmed compromise claim
- No automated response actions

## JSON Reporting

Default reports retain exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

Without `--include-explanations`, alert dictionaries remain unchanged. With the flag, each alert receives a nested `explanation` object. The report does not add a top-level `explanations` field.

## Known Limitations

- Not a production EDR
- No persistent monitoring daemon
- No dashboard
- Explanation export requires an explicit CLI flag
- Real AI-assisted or LLM-based explanation is not implemented
- Ubuntu ARM64 validation for this milestone is pending

## Author

Kavisara Samarakoon
