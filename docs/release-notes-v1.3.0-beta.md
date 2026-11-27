# SentinelLite AI v1.3.0-beta — Versioned Alert-Report Schema v1

## Release Status

`v1.3.0-beta` is published as a
[GitHub pre-release](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.3.0-beta).

| Publication field | Value |
| --- | --- |
| Published at | `2026-11-27T07:45:25Z` |
| Draft | `false` |
| Prerelease | `true` |
| Release ID | `460294277` |
| Git tag | `v1.3.0-beta` |
| Annotated tag SHA | `b13fe9c6030b2422ab45a7df8060f133fa452f8a` |
| Tag target commit | `bf84cf93b40fa73f6489cc4312b2769bcb93204f` |

The CLI prints `SentinelLite AI v1.3.0-beta`. Python package metadata normalizes
`sentinellite.__version__` to `1.3.0b0`. SentinelLite AI is not published to PyPI.

## Release Assets and SHA-256 Hashes

All three uploaded assets were downloaded and checksum-verified before publication.

| Asset | SHA-256 |
| --- | --- |
| `sentinellite_ai-1.3.0b0-py3-none-any.whl` | `02fb7409a3e071d561700b9783af2136307669aaa332260d4324e20ea3c0dab3` |
| `sentinellite_ai-1.3.0b0.tar.gz` | `c17e285ccf6e99cad8c8e6e2f5ef284da542adc6312fd4f9fd843128df0f128d` |
| `SHA256SUMS.txt` | `9c18c75a257c7c7d0668200c0a23b419f781041055bef64c8a93f9f25ec24fc4` |

## Key Changes in v1.3.0-beta (Issue #14, PR #15)

### Versioned Alert-Report Schema v1

- Newly generated alert reports emit a versioned schema-v1 envelope with exactly six
  top-level fields: `schema_version`, `report_id`, `report_type`, `generated_at`,
  `alert_count`, and `alerts`.
- `schema_version` is integer `1` (never a boolean, float, string, or null).
- Optional deterministic explanations are nested per alert (`explanation`) rather than in a
  top-level `explanations` field, keeping one consistent envelope for both default and
  explained reports.

### Canonical Parsing and Strict JSON Validation

- `parse_report_json()` provides canonical parsing and strict validation for alert reports.
- Every alert must contain all 15 required fields with strict type, score range (`0..100`,
  non-boolean integers), and severity/risk-level enum checks (`info`, `low`, `medium`,
  `high`, `critical`).
- Unknown report or alert fields, malformed JSON, incomplete alerts, and invalid optional
  explanations are rejected without partial projections.
- Unsupported future schema versions (for example, `schema_version: 2`) are rejected cleanly
  via `UnsupportedSchemaError`.

### Verified Legacy-Unversioned Format Compatibility

- Complete historical unversioned reports (matching the `v1.0.0-beta` through `v1.2.0-beta`
  five-field envelope) remain readable as `legacy-unversioned`.
- Legacy reports are never rewritten or silently upgraded when read, listed, shown, or
  exported.

### Report Writer, Review CLI, and Dashboard Integration

- `sentinellite reports list` distinguishes `valid (v1)`, `valid (legacy)`, `unsupported`,
  and `invalid` candidates, retains valid entries in mixed directories, and exits with code 1
  if any candidate fails validation.
- `sentinellite reports show` displays the report contract and version (`schema-v1` / `1` or
  `legacy-unversioned` / `unversioned`) and exits with code 1 on invalid or unsupported inputs
  without partial projections.
- `sentinellite dashboard export` loads complete schema-v1 and legacy-unversioned reports,
  counts invalid, unsupported, unreadable, or oversized (> 2 MiB) inputs as skipped, ignores
  symlinks and subdirectories, escapes report-derived text, and omits raw evidence.

### Report Privacy and Validation Safeguards

- `sentinellite reports export-notification` preserves notification summary `schema_version` `1`
  and writes to a separate output path without overwriting existing outputs or modifying the
  source report byte-for-byte.
- Notification summaries include at most 20 alerts, record `omitted_alert_count`, and exclude
  alert messages, raw evidence, explanation text, usernames, addresses, paths, process
  details, and hashes.

### Synthetic Fixtures and Regression Coverage

- `tests/fixtures/report_schema/` provides 16 schema fixtures covering schema-v1,
  historical-format replicas of unversioned reports, unsupported future versions, and
  malformed inputs.
- Note: the legacy compatibility fixtures are **historical-format replicas** constructed to
  match the `v1.0.0-beta`–`v1.2.0-beta` contract, not actual historical generated artifacts.

## Release Validation

- **Ubuntu x86-64 CI** passed on Python 3.11 and 3.14.
- **Final macOS validation** passed on macOS 27.2.1 ARM64 with Python 3.14.6 and 1,991 tests.
  Ruff, `pip check`, `git diff --check`, wheel and sdist builds, isolated wheel installation,
  and synthetic smoke tests passed.
- **Downloaded wheel validation** passed isolated installation and synthetic demo and dashboard
  smoke tests. Manual Safari inspection showed one report, three alerts, highest severity
  medium, and zero skipped files.
- **Pre-version-bump `main` baseline (`d278d6af6772546a6730c8323935202e7811b228`, PR #15)**:
  Ubuntu CI passed on Python 3.11 and Python 3.14 (1,990 tests each), including all 16
  schema fixtures and schema/notification contract smoke checks.

### Deferred Ubuntu ARM64 Validation

On November 27, 2026, the owner deferred exact-wheel Ubuntu ARM64 validation because the
ARM-SecNet VM was unavailable. This exception applies only to `v1.3.0-beta`. The check
remains unverified, and future releases retain their validation requirements.
[Issue #17](https://github.com/kavisara-samarakoon/sentinellite-ai/issues/17) tracks the exact-wheel run.

These checks do not claim universal Linux or ARM64 compatibility.

## Compatibility Boundaries

- Published `v1.0.0-beta` through `v1.2.0-beta` artifacts retain their historical unversioned
  report format.
- `v1.3.0-beta` consumers can read complete `legacy-unversioned` reports as well as
  `schema-v1` reports, while `v1.2.0-beta` and earlier releases do not understand
  `schema_version: 1`.
- See [Data Contracts](data-contracts.md) and the [Release Checklist](release-checklist.md)
  for full contract rules and release gates.

## Defensive Scope and Limitations

This is not a production EDR release. SentinelLite AI is a beta-stage, local, on-demand,
defensive endpoint observation and report-review CLI, not antivirus, a SIEM/SOC platform,
a malware remover, or an enterprise security platform. Alerts do not prove malware or
compromise.

- No real AI or LLM execution; explanations remain deterministic local templates.
- No daemon, scheduler, background service, or live monitoring.
- No external notification delivery or network requests.
- No active network scanning, public scanning, packet sending, or exploitation.
- No automatic remediation, malware removal, firewall changes, or process killing.
- No PyPI publishing as part of this milestone.

## Release History

The previous published milestone was [v1.2.0-beta](release-notes-v1.2.0-beta.md), which
introduced the static dashboard and recorded the ARM-SecNet lab validation.
