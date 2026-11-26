# SentinelLite AI v1.3.0-beta — Versioned Alert-Report Schema v1 (Release Candidate)

## Release Status

`v1.3.0-beta` is a **release candidate in preparation** and is **not yet published**.

- Target GitHub pre-release: `v1.3.0-beta` (publication **pending**)
- Published at: **pending**
- Git tag: **pending**
- Annotated tag SHA: **pending**
- Tag target commit: **pending**

The CLI display version is `1.3.0-beta`; normalized Python package metadata is `1.3.0b0`
(derived dynamically from `sentinellite.__version__`). SentinelLite AI is not published to PyPI.

The currently published GitHub pre-release remains
[v1.2.0-beta](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.2.0-beta)
(see the [v1.2.0-beta release notes](release-notes-v1.2.0-beta.md)).

## Release Assets and SHA-256 Hashes

Final release asset hashes are **pending** until the final reviewed release commit is tagged
and artifacts are built from that exact commit:

| Asset | SHA-256 |
| --- | --- |
| `sentinellite_ai-1.3.0b0-py3-none-any.whl` | **pending** |
| `sentinellite_ai-1.3.0b0.tar.gz` | **pending** |
| `SHA256SUMS.txt` | **pending** |

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

## Validation Status and Source-State Distinctions

- **Pre-version-bump `main` baseline (`d278d6af6772546a6730c8323935202e7811b228`, PR #15)**:
  Ubuntu CI passed on Python 3.11 and Python 3.14 (1,990 tests each), including all 16
  schema fixtures and schema/notification contract smoke checks.
- **macOS release-candidate preparation**: Local validation (editable install, `pip check`,
  Ruff, full Pytest suite, `git diff --check`, wheel/sdist build, isolated wheel install,
  version/help/bare-status checks, synthetic auth/report/notification/doctor/demo/dashboard
  smoke checks) is executed on the uncommitted candidate before the release-candidate commit.
- **Ubuntu ARM64 exact-candidate validation**: **Pending** execution on the ARM-SecNet Ubuntu
  ARM64 VM against the committed release-candidate source/artifact.
- **Final exact-commit validation and artifact build**: **Pending** final release-candidate
  commit.

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

The current published milestone is [v1.2.0-beta](release-notes-v1.2.0-beta.md).
Its historical publication details remain unchanged; they do not describe this release candidate.
