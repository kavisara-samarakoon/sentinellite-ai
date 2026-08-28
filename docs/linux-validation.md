# Linux/Ubuntu ARM64 Validation

SentinelLite AI, including baseline-backed file integrity monitoring, was validated successfully in an Ubuntu ARM64 virtual machine. This document records the observed environment, quality checks, CLI status, and scan summaries from that validation run.

## v0.7 Authentication Source Compatibility Validation Status

The v0.7 automated validation is defined for common Linux authentication log source inventory and representative traditional text fixtures. This validation is intentionally separated from the earlier Ubuntu ARM64 runtime record below.

Current v0.7 status:

- Ubuntu/Debian-style fixture validation: defined using `examples/auth_logs/sample_ubuntu_auth.log`
- RHEL/Fedora-style fixture validation: defined using `examples/auth_logs/sample_rhel_secure.log`
- Fixture pipeline, five-field JSON compatibility, and v0.6 report review validation: defined
- `auth-sources list` inventory behavior: defined as local and read-only
- macOS development validation: pending
- Ubuntu ARM64 validation for v0.7: pending
- Real authorized `/var/log/auth.log` validation: pending
- RHEL/Fedora runtime validation: not yet performed or claimed

The fixture checks confirm only the currently supported traditional failed SSH password, accepted SSH password, and sudo record shapes. They do not establish compatibility with every record produced by Ubuntu, Debian, RHEL, or Fedora.

`/var/log/auth.log` and `/var/log/secure` are candidate paths rather than guaranteed defaults. Availability depends on the distribution and local logging configuration. `auth-sources list` inventories these candidates without reading or printing log contents and without starting `scan-auth` automatically. A real system path must still be selected explicitly with existing authorized read access.

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

`PYTHONPATH=src` was exported during local VM validation.

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
