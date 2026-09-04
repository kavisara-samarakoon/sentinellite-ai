# Linux/Ubuntu ARM64 Validation

SentinelLite AI, including baseline-backed file integrity monitoring, was validated successfully in an Ubuntu ARM64 virtual machine. This document records the observed environment, quality checks, CLI status, and scan summaries from that validation run.

## v1.0.0-beta Final Candidate Validation

Final candidate validation passed on macOS Apple Silicon and Ubuntu ARM64 at release-candidate
commit `c873330`. These results validate that candidate source state only. The later final
tagged-release artifact rebuild, checksums, and publication are recorded separately in the
[v1.0.0-beta release notes](release-notes-v1.0.0-beta.md).

### macOS Final Candidate Validation

| Field | Observed Value |
|---|---|
| Operating system | macOS / Darwin |
| Architecture | Apple Silicon `arm64` |
| Python version | `3.14.6` |
| Release-candidate commit | `c873330` |

The validation used a clean temporary clone. Editable installation and `python -m pip check`
passed. The console and module entry points both passed and reported exactly
`SentinelLite AI v1.0.0-beta`. Ruff passed, all 597 tests passed, and `git diff --check`
passed.

The authentication workflow used only the deterministic bundled Ubuntu fixture,
`examples/auth_logs/sample_ubuntu_auth.log`. It produced:

- 3 authentication events
- 3 security events
- 3 detection matches
- 3 scored alerts

`reports list`, `reports show`, and local notification-summary export passed. The alert report
retained exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

There was no top-level `explanations` field. The separate notification summary retained
`schema_version = 1`, `alert_count = 3`, `included_alert_count = 3`, and
`omitted_alert_count = 0`. Privacy assertions passed for fixture usernames, addresses,
command text, and alert-message text.

The wheel and source distribution built successfully. Wheel package metadata reported
`1.0.0b0`; MIT metadata and the license file, the `sentinellite` console entry point, and
`sentinellite/config/default.yaml` were present. Isolated wheel installation passed outside
the repository checkout. The final disposable clone was cleaned successfully.

Candidate-validation artifact hashes from this macOS run were:

- Wheel SHA-256: `23905088687520ca316d6a2fb690f6494c1e7cfea7b0106d191f629f660f57c7`
- Source distribution SHA-256: `129d54db9a8c7190e7cdd0b1595425d58d6d5f0defaa0c4d5342bb8e9f765cec`

These are validation-run candidate hashes only. They are not final GitHub release artifact
hashes. Final release artifacts were later rebuilt from the exact merged and tagged commit;
their official hashes are recorded in the v1.0.0-beta release notes.

### Ubuntu ARM64 Final Candidate Validation

| Field | Observed Value |
|---|---|
| Operating system | Ubuntu Linux |
| Kernel | `7.0.0-30-generic` |
| Architecture | `aarch64` |
| Python version | `3.14.4` |
| Ruff version | `0.16.6` |
| Pytest version | `9.1.1` |
| Release-candidate commit | `c873330` |
| Final worktree | Clean at `c873330` |

The validation used a clean temporary clone. Editable installation and `python -m pip check`
passed. Both entry points reported exactly `SentinelLite AI v1.0.0-beta` and exposed the
expected command tree. Ruff passed, all 597 tests passed, and `git diff --check` passed.

The explicit TOML status regression passed consistently through the console and module entry
points:

| Explicit module setting | Displayed status |
|---|---|
| `authentication = false` | Disabled |
| `process = false` | Disabled |
| `network = false` | Disabled |
| `file_integrity = false` | Disabled |

The CLI displayed `Local Defensive Observation CLI`, `Status: AVAILABLE`, and
`Real AI / LLM Execution: Not implemented`.

Authentication source inventory reported `/var/log/auth.log` as available and
`/var/log/secure` as missing. This was inventory only. Neither path was read or passed to
`scan-auth`, and this validation does not claim that a real host authentication log was
scanned.

Fixture validation used only the bundled
`examples/auth_logs/sample_ubuntu_auth.log`. It produced:

- 3 authentication events
- 3 security events
- 3 detection matches
- 3 scored alerts

`reports list`, `reports show`, and local notification-summary export passed. The notification
recorded 3 total alerts, 3 included alerts, and 0 omitted alerts.

The alert report retained exactly the five established top-level fields—`report_id`,
`report_type`, `generated_at`, `alert_count`, and `alerts`—with no top-level `explanations`
field. The separate notification summary retained `schema_version = 1`, and privacy
assertions passed.

Wheel metadata reported `1.0.0b0`. The wheel included MIT metadata and the license file, the
`sentinellite` console entry point, and `sentinellite/config/default.yaml`. The source
distribution included `LICENSE`, `pyproject.toml`, and the packaged default YAML. Isolated
wheel installation and `pip check` passed outside the checkout.

`pip-audit` reported `No known vulnerabilities found`. It skipped `sentinellite-ai` itself
because this local beta package is not published on PyPI. That expected skip is not a
vulnerability finding.

Candidate-validation artifact hashes from this Ubuntu ARM64 run were:

- Wheel SHA-256: `57d5240d12c094883c983b013a9815d5ce8ed9e4232085e5bec07ea9106d12ab`
- Source distribution SHA-256: `e9e7ddb456b3ba1549d7d1ba2cc0f87c11f2260c5554d3a52a8fb5291931e432`

These are validation-run candidate hashes only. They are not final GitHub release artifact
hashes. Final release artifacts were later rebuilt from the exact merged and tagged commit;
their official hashes are recorded in the v1.0.0-beta release notes.

The sections below are preserved historical validation records. Their version-specific
commands and results are not current v1 beta claims.

## v0.9 Installation Validation Status

Final v0.9 Ubuntu ARM64 validation passed. This validation covered installed-package behavior, both supported entry styles, fixture-based scan and review behavior, notification compatibility, and wheel contents without scanning a real host authentication log.

### v0.9 Ubuntu ARM64 Environment

| Field | Observed Value |
|---|---|
| Operating system | Linux |
| Architecture | `aarch64` |
| Python version | `3.14.4` |
| Ruff version | `0.16.3` |
| Pytest version | `9.1.1` |
| Ruff result | Passed |
| Pytest result | 588 passed |
| Working tree after validation | Clean |

### v0.9 Installation and Entry-Point Results

- Editable installation: passed
- `python -m pip check`: passed
- `sentinellite --version`: passed and displayed `SentinelLite AI v0.9.0-alpha`
- `python -m sentinellite --version`: passed and displayed `SentinelLite AI v0.9.0-alpha`
- Bare `sentinellite` status from `/tmp`: passed
- Bare `python -m sentinellite` status from `/tmp`: passed

### v0.9 Authentication Fixture and Report Results

`auth-sources list` completed successfully. It inventoried `/var/log/auth.log` as available and `/var/log/secure` as missing. This was inventory only: the command did not read either log, and the available `/var/log/auth.log` was not passed to `scan-auth`.

Scan validation used the bundled `examples/auth_logs/sample_ubuntu_auth.log` fixture. It produced 3 authentication events and 3 alerts. `reports list` and `reports show` both accepted the generated alert report.

The generated alert report retained exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

No top-level `explanations` field was added. Exporting the report produced a separate notification summary with 3 included alerts and 0 omitted alerts. Notification privacy compatibility passed, and the notification artifact retained its independent schema rather than becoming a SentinelLite alert report.

### v0.9 Wheel Results

The wheel build and metadata/resource validation passed. The wheel contained:

- the MIT License
- `sentinellite/config/default.yaml`
- `sentinellite-ai` package metadata
- the `sentinellite` console entry point

This validation supports local package and installation readiness only. `v0.9.0-alpha` is a published GitHub pre-release alpha milestone and is not a production EDR release. It does not provide real AI or LLM execution, external notification delivery, daemon or background monitoring, or automatic remediation.

## v0.8 Notification Export Validation Status

The v0.8 local notification summary export validation passed on macOS development, GitHub PR CI, and an Ubuntu ARM64 virtual machine. The Ubuntu validation covered the complete local fixture-to-report-to-notification workflow while preserving the existing alert report and keeping the notification schema separate.

Current v0.8 status:

- GitHub PR #7 CI: passed for both `push` and `pull_request`
- macOS development validation: passed
- Ubuntu ARM64 validation: passed
- Local notification export smoke: passed
- Existing alert-report compatibility and report review: passed
- Notification schema and privacy compatibility: passed

### v0.8 Ubuntu ARM64 Results

| Field | Observed Value |
|---|---|
| Operating system | Linux |
| Architecture | `aarch64` |
| Python version | `3.14.4` |
| Ruff | Passed |
| Pytest | 568 passed |
| CLI version | `SentinelLite AI v0.8.0-alpha` |
| Notification smoke | Passed |
| Working tree after validation | Clean |

The bundled Ubuntu/Debian-style authentication fixture produced 3 authentication events and 3 alerts. Exporting its generated report produced a local notification summary with 3 included alerts and 0 omitted alerts.

The original SentinelLite alert report remained compatible with the established five-field top-level schema:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

No top-level `explanations` field was added. `reports list` and `reports show` continued to accept and display the original generated report after notification export.

The notification artifact passed validation against its separate schema, including `schema_version`, `output_type`, source metadata, alert counts, severity counts, risk-level counts, and privacy-minimized alert entries. It was not treated as a SentinelLite alert report.

Privacy validation confirmed that these sensitive fixture values were not copied into the notification JSON:

- `labadmin`
- `demo-user`
- `192.0.2.10`
- `192.0.2.11`
- `/usr/bin/id`
- `Failed SSH login attempt`
- `Successful SSH login`

The Ubuntu worktree ended clean. This validation covers local notification summary export only. It does not claim production readiness, external notification delivery, or email, Slack, Discord, webhook, or SMS integration.

## v0.7 Authentication Source Compatibility Validation Status

The v0.7 validation passed on macOS development, GitHub CI, and an Ubuntu ARM64 virtual machine. Its authentication scan checks used representative traditional text fixtures and are intentionally separated from both real host-log scanning and the earlier Ubuntu ARM64 runtime record below.

Current v0.7 status:

- GitHub PR CI: passed for both `push` and `pull_request`
- macOS development validation: passed
- Ubuntu ARM64 validation for v0.7: passed
- Ubuntu/Debian-style fixture validation: passed using `examples/auth_logs/sample_ubuntu_auth.log`
- RHEL/Fedora-style fixture validation: passed using `examples/auth_logs/sample_rhel_secure.log`
- Fixture pipeline, five-field JSON compatibility, and v0.6 report review validation: passed
- `auth-sources list` inventory behavior: passed as local and read-only
- Real authorized `/var/log/auth.log` scan validation: not performed or claimed
- RHEL/Fedora runtime validation: not performed or claimed

### v0.7 Ubuntu ARM64 Results

| Field | Observed Value |
|---|---|
| Operating system | Linux |
| Architecture | `aarch64` |
| Python version | `3.14.4` |
| Ruff | Passed |
| Pytest | 531 passed |
| CLI version | `SentinelLite AI v0.7.0-alpha` |
| Working tree after validation | Clean |

`auth-sources list` completed successfully on the Ubuntu ARM64 VM. It inventoried `/var/log/auth.log` as available and `/var/log/secure` as missing. This confirms candidate inventory behavior only: the command did not read or scan the available host log, and no real `/var/log/auth.log` scan was performed or claimed.

The explicit fixture scans produced these results:

| Fixture | Authentication Events | Alerts |
|---|---:|---:|
| Ubuntu/Debian-style `sample_ubuntu_auth.log` | 3 | 3 |
| RHEL/Fedora-style `sample_rhel_secure.log` | 3 | 3 |

These are fixture-format results, not claims of comprehensive distribution support. In particular, the RHEL/Fedora-style fixture does not constitute Fedora or RHEL runtime validation.

Report review smoke validation also passed. `reports list` displayed a generated fixture report as valid, and `reports show` displayed its summary and stored alerts. Generated JSON preserved exactly the five established top-level fields—`report_id`, `report_type`, `generated_at`, `alert_count`, and `alerts`—and did not add a top-level `explanations` field.

The fixture checks confirm only the currently supported traditional failed SSH password, accepted SSH password, and sudo record shapes. They do not establish compatibility with every record produced by Ubuntu, Debian, RHEL, or Fedora.

`/var/log/auth.log` and `/var/log/secure` are candidate paths rather than guaranteed defaults. Availability depends on the distribution and local logging configuration. `auth-sources list` inventories these candidates without reading or printing log contents and without starting `scan-auth` automatically. A real system path must still be selected explicitly with existing authorized read access; this v0.7 validation did not perform a real host-log scan.

## Earlier Ubuntu ARM64 Validation Result

Result: **Passed**

In the earlier recorded validation, the application started in its intended Linux runtime mode, all then-implemented monitoring modules were available, the automated quality checks passed, and each scan command completed successfully.

## Environment

| Field | Observed Value |
|---|---|
| Environment | Ubuntu ARM64 VM |
| Hostname | `KavisaraUbuntuARM64` |
| Operating system | Linux |
| OS release | `7.0.0-27-generic` |
| Architecture | `aarch64` |
| Python version | `3.14.4` |
| Runtime mode | Linux target environment |

`PYTHONPATH=src` was exported during this historical pre-packaging validation. Current
installed development and release flows do not require or recommend `PYTHONPATH`.

## Validated Source State

| Field | Value |
|---|---|
| Branch | `main` |
| Latest commit | `1e41948 Make missing baseline CLI test robust` |

## Quality Checks

| Check | Result |
|---|---|
| Ruff | Passed |
| Pytest | 207 passed |

## CLI Status

The default CLI status display reported:

| Module | Status |
|---|---|
| Authentication Monitor | Enabled |
| Process Monitor | Enabled |
| Network Monitor | Enabled |
| File Integrity Monitor | Enabled |
| JSON Reporting | Enabled |
| AI-Assisted Explanation | Planned |

AI-assisted explanation was not treated as implemented during this validation.

## Validated Commands

The existing CLI workflows completed successfully:

```bash
python -m sentinellite
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
python -m sentinellite scan-process
python -m sentinellite scan-network
python -m sentinellite scan-files README.md
```

The baseline-backed file integrity workflow also completed successfully:

```bash
python -m sentinellite baseline-files README.md pyproject.toml --baseline-path file-integrity-baseline.json
python -m sentinellite scan-files-baseline --baseline-path file-integrity-baseline.json
```

## Scan Validation

### Authentication Scan

| Metric | Observed Value |
|---|---:|
| Authentication events found | 4 |
| Security events created | 4 |
| Detection matches | 4 |
| Scored alerts | 4 |

### Process Scan

| Metric | Observed Value |
|---|---:|
| Processes found | 194 |
| Security events created | 194 |
| Detection matches | 0 |
| Scored alerts | 0 |

The absence of process alerts indicates that no configured process rule matched the observed process metadata. It is not a broader security guarantee.

### Network Scan

| Metric | Observed Value |
|---|---:|
| Connections found | 25 |
| Security events created | 25 |
| Detection matches | 13 |
| Scored alerts | 13 |

Network alerts are expected in a live VM because active network connections exist and may meet investigation-focused rule conditions. These alerts identify observations for review; they do not classify a connection as malicious or claim malware detection.

### File Integrity Scan

| Metric | Observed Value |
|---|---:|
| Files checked | 1 |
| Security events created | 1 |
| Detection matches | 0 |
| Scored alerts | 0 |

The file integrity result records the state of the explicitly supplied path during the validation run. No alert means that no configured file integrity rule matched that observation.

## Baseline-Backed File Integrity Validation

A baseline was created for `README.md` and `pyproject.toml`, then scanned without changing either file. The unchanged scan reported:

| Metric | Observed Value |
|---|---:|
| Files checked | 2 |
| Comparisons | 2 |
| Security events | 2 |
| Detection matches | 0 |
| Scored alerts | 0 |

A separate changed-file demonstration used `/tmp/sentinellite-baseline-demo/demo.txt`. After the file was modified, SentinelLite AI generated the expected alert:

```text
FIM-004  MEDIUM (70)  File Changed Compared With Baseline
```

Temporary baseline, report, and demonstration files were removed after testing. `git status --short` returned no output after cleanup, confirming a clean working tree.

## Validation Scope and Limitations

- The validation confirms that SentinelLite AI runs successfully in the tested Ubuntu ARM64 VM environment.
- Detection results are defensive, investigation-focused signals and are not proof of compromise or malware.
- AI-assisted explanation remains planned and was not validated as an implemented capability.
- Baseline-backed file integrity monitoring is implemented and validated; it does not modify monitored files.
- No private tokens, credentials, or other sensitive values are included in this document.
- Screenshots are intentionally not included at this stage.

Future validation can extend this record with additional Linux distributions, Python versions, repeatability checks, and screenshots when appropriate.
