# SentinelLite AI v0.2.0-alpha Release Notes

## Release Type

Alpha defensive cybersecurity learning and portfolio milestone. This release is intended for controlled development, demonstration, and authorized defensive security use, not production deployment.

## Summary

SentinelLite AI `v0.2.0-alpha` focuses on baseline-backed file integrity monitoring. It can record a trusted state for explicitly selected paths, persist that baseline, compare later observations with it, normalize comparison events, and produce investigation-focused alerts for relevant changes.

AI-assisted explanation remains planned and is not implemented in this release.

## Baseline-Backed File Integrity Milestone

- Versioned file integrity baseline model
- JSON baseline persistence
- Current-state-to-baseline comparison logic
- Baseline comparison event normalization
- Investigation-focused `FIM-004` through `FIM-008` detection rules
- Baseline-backed scan pipeline with risk scoring and JSON alert reporting
- `baseline-files` CLI command for explicitly selected paths
- `scan-files-baseline` CLI command for paths stored in an explicitly supplied baseline
- README and CI updates for the expanded workflow and automated coverage
- Successful Ubuntu ARM64 validation
- 207 automated tests passing

## CLI Commands

Create a baseline for explicitly selected files:

```bash
python -m sentinellite baseline-files README.md pyproject.toml --baseline-path file-integrity-baseline.json
```

Compare current observations with the saved baseline:

```bash
python -m sentinellite scan-files-baseline --baseline-path file-integrity-baseline.json
```

## Validation

The release was validated successfully on an Ubuntu ARM64 VM at commit `1e41948 Make missing baseline CLI test robust`. Ruff passed, and Pytest passed with 207 tests. Both unchanged-baseline behavior and a changed-file demonstration were validated; the latter generated `FIM-004 File Changed Compared With Baseline` at `MEDIUM (70)`.

See the [Linux/Ubuntu ARM64 validation report](linux-validation.md) for the full environment, commands, results, and cleanup record.

## Safety Notes

- Defensive-only functionality
- Explicit file paths only
- No recursive scanning
- No packet sending
- No port scanning
- No exploit code
- No malware functionality
- Does not modify monitored files
- AI-assisted explanation is planned, not implemented

Baseline creation writes only the explicitly requested JSON baseline file, and baseline scanning writes only its JSON alert report. Detection results are investigation signals, not proof of compromise or malware classification.

## Known Limitations

- Not a production EDR
- No daemon mode yet
- No dashboard yet
- No real AI explanation yet

## Author

Kavisara Samarakoon
