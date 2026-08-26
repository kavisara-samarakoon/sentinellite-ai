# SentinelLite AI v0.3.0-alpha Release Notes

## Release Status

In-development alpha milestone for controlled demonstration, authorized defensive security learning, and portfolio review. `v0.3.0-alpha` has not been released yet.

## Release Focus

This milestone adds deterministic alert explanations to CLI scan output. When a scan produces scored alerts, SentinelLite AI displays local, rule-based investigation guidance after the existing alert table. Scans with no scored alerts retain their existing output and do not display an empty explanation section.

AI-assisted explanation is still planned for the future and is not implemented in this milestone.

## Added

- Frozen `AlertExplanation` data model with validated dictionary serialization
- Deterministic explanation templates for existing AUTH, PROC, NET, and FIM rules
- Local explanation generator with cautious generic guidance for unknown rule IDs
- Rich CLI explanation panels with conditional evidence display
- Deterministic explanation display for:
  - `scan-auth`
  - `scan-process`
  - `scan-network`
  - `scan-files`
  - `scan-files-baseline`
- Defensive evidence summaries built only from fields already available in scored alerts
- Lightweight CI assertion that the authentication smoke scan displays the deterministic explanation section

## Validation

- Ruff: passed
- Pytest: 288 tests passed
- macOS development validation: passed for CLI status, authentication scanning, process observation, network observation, selected-file observation, baseline creation, and baseline scanning
- Authentication smoke output confirmed deterministic explanation panels
- JSON report compatibility confirmed by tests
- Ubuntu ARM64 validation for the `v0.3.0-alpha` explanation milestone: passed

The `v0.3.0-alpha` explanation milestone was validated successfully on an Ubuntu ARM64 VM at commit `ae67254 Document deterministic alert explanations`. Ruff passed, Pytest passed with 288 tests, the CLI displayed `SentinelLite AI v0.3.0-alpha`, authentication scan explanations were displayed, and a changed-file baseline demonstration generated `FIM-004 File Changed Compared With Baseline` with deterministic explanation output.

## Safety Scope

- Local deterministic templates only
- No LLM, AI model, or external API calls
- No claim that an alert detects malware
- No automatic claim that a host or account is compromised
- No automated response actions
- No JSON alert report schema change
- Evidence summaries contain only fields already supplied by existing alert data

Explanations provide investigation guidance. Possible causes are review prompts rather than conclusions about what occurred.

## JSON Reporting

JSON reports remain unchanged in `v0.3.0-alpha`. Explanation objects and explanation templates are not written into report files in this milestone; the new presentation is terminal-only.

## Known Limitations

- Not a production EDR
- No daemon mode
- No dashboard
- JSON explanation export is not included yet
- Real AI-assisted explanation is not implemented yet

## Author

Kavisara Samarakoon
