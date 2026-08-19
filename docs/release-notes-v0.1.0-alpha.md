# SentinelLite AI v0.1.0-alpha Release Notes

## Release Type

Alpha prototype and defensive cybersecurity learning and portfolio milestone.

This release demonstrates the project's current architecture and end-to-end monitoring workflows. It is intended for controlled development, demonstration, and authorized defensive security learning rather than production deployment.

## Summary

SentinelLite AI `v0.1.0-alpha` provides end-to-end, CLI-based Linux endpoint monitoring workflows for:

- Authentication log analysis
- Process observation
- Active network connection observation
- Selected file integrity observation
- Rule-based detection
- Risk scoring
- JSON reporting

The prototype collects security-relevant observations, normalizes them into security events, evaluates transparent detection rules, scores matching alerts, and writes structured results for review.

## Implemented Modules

- **Authentication Monitor** — analyzes authentication log events, including SSH login activity and sudo usage.
- **Process Monitor** — observes running processes and evaluates investigation-focused process rules.
- **Network Monitor** — observes active network connections without sending packets.
- **File Integrity Monitor** — records metadata and SHA-256 hashes for explicitly selected paths.
- **JSON Reporter** — writes structured alert reports for review and integration.
- **Risk Scoring** — assigns scores and risk levels to rule matches.
- **GitHub Actions CI** — runs automated quality checks for repository changes.

## CLI Commands

Display the main application status:

```bash
python -m sentinellite
```

Analyze the included sample authentication log:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
```

Observe running processes:

```bash
python -m sentinellite scan-process
```

Observe active network connections:

```bash
python -m sentinellite scan-network
```

Observe one selected file:

```bash
python -m sentinellite scan-files README.md
```

Observe multiple selected files:

```bash
python -m sentinellite scan-files README.md pyproject.toml
```

## Validation

The `v0.1.0-alpha` prototype has reached the following validation milestones:

- 135 automated tests passing
- Ruff passing
- GitHub Actions CI passing
- Ubuntu ARM64 VM validation completed

See the [Linux/Ubuntu ARM64 validation report](linux-validation.md) for the recorded environment and scan results.

## Safety Scope

SentinelLite AI is a defensive-only project. Its implemented monitoring workflows use read-only observations and are intended for authorized systems and data.

This release includes:

- No exploit code
- No malware
- No credential theft
- No packet sending
- No port scanning
- No file repair or modification

Detection results are investigation-focused signals. They are not proof of compromise and do not claim to classify malware.

## Known Limitations

- There is no persistent monitoring daemon yet.
- Baseline-backed file change detection is not implemented yet.
- AI-assisted alert explanation is not implemented yet.
- The current file integrity module observes explicitly selected paths only.
- The current network module observes active connections only.

These limitations are intentional for the current alpha scope and should be considered when evaluating or demonstrating the project.

## Suggested Next Roadmap

- Add baseline-backed file integrity change detection.
- Improve Linux authentication log support.
- Improve report summaries.
- Add AI-assisted alert explanation.
- Add a packaging and installation workflow.

## Author

Kavisara Samarakoon

