# SentinelLite AI v1.1.0-beta Release Notes

## Release Status

`v1.1.0-beta` is a release candidate, not yet published as a GitHub release. The current
published release remains `v1.0.0-beta`. Candidate preparation does not create or move
release tags and does not publish artifacts. SentinelLite AI is not on PyPI yet.

The CLI display version is `SentinelLite AI v1.1.0-beta`. Python package metadata normalizes
the version to `1.1.0b0`, derived from the single source `sentinellite.__version__`.

## Release Focus

This candidate improves public usability: helping a new user verify a local installation,
run a fixture-first safe demo, and review a saved report. It also documents optional use
inside an ARM-SecNet Ubuntu ARM64 lab. SentinelLite AI remains a beta-stage, local,
on-demand, defensive endpoint observation and report-review CLI.

## Included Improvements

- `sentinellite demo` processes bundled synthetic authentication records in memory using
  the existing normalization, detection, scoring and report pipeline. It writes a normal
  JSON report, prints the saved path, and suggests `sentinellite reports list` and
  `sentinellite reports show <REPORT_PATH>`. It does not read real logs, observe processes,
  network connections or files, or send network traffic.
- `sentinellite doctor` performs local installation readiness checks: SentinelLite and
  Python versions, platform/system, machine architecture, packaged defaults, report
  directory write access, and required dependency imports. It prints PASS/WARNING/FAIL
  results, needs no root privileges, and performs no observation or network activity.
  Its write check creates and removes a temporary file without altering existing reports.
- The [ARM-SecNet integration guide](integrations/arm-secnet.md) covers the Apple Silicon /
  UTM / Ubuntu ARM64 environment, installation, safe commands, report review, optional
  authorized observations, and an evidence checklist. This is documentation-based
  integration only: the repositories remain separate with no runtime dependency.
- README and the [demo guide](demo-guide.md) provide an installation-check and synthetic
  demo workflow before any optional observations of an authorized host.

## Installation and Compatibility

Before release, install from `feature/v1.1-product-usability`. After release, the
`v1.1.0-beta` wheel can be used. The already published `v1.0.0-beta` wheel does not include
`doctor` or `demo`; this candidate does not modify that wheel.

- Python 3.11 or newer is required. Console and module entry points remain supported.
- `doctor` and `demo` support `--output-dir`; selected TOML reporting settings remain
  available. Demo uses built-in rules and can store deterministic explanations.
- Doctor failures exit with code 1. Passes and warnings exit with code 0. Non-Linux systems
  receive a warning because endpoint observation targets Linux.
- Typer and Rich must be installed for the CLI, including doctor, to start. Missing
  `psutil` or PyYAML can be reported by doctor without preventing CLI startup.
- Existing scan and report-review behavior remains unchanged. This candidate preparation
  changes no runtime behavior beyond the version display.
- The JSON report schema is unchanged: the top-level fields remain `report_id`,
  `report_type`, `generated_at`, `alert_count`, and `alerts`. Optional explanations remain
  nested in individual alerts. The separate local notification-summary schema is unchanged.

## Validation

The automated suite contains 620 tests covering CLI commands, local installation checks,
synthetic demo boundaries, configuration, collectors, detection, scoring, reports,
explanations, entry points and packaging. Candidate validation runs dependency checks,
both version entry points, Ruff, all 620 automated tests, a wheel/source build and
`git diff --check`.

This guide and the automated suite do not establish completed ARM-SecNet runtime
validation for this candidate. Historical `v1.0.0-beta` platform results remain historical
evidence. Candidate CI, Ubuntu ARM64 lab validation and publication are separate steps;
none is implied complete by these notes.

## Defensive-Only Scope

This is not a production EDR release. SentinelLite AI is not antivirus, a SIEM/SOC platform,
a malware remover, or an enterprise security platform. It is not real AI/LLM-powered.
Local checks and synthetic demonstrations do not establish production readiness.

- No real AI or LLM execution; explanations use deterministic local templates.
- No daemon, scheduler, background service, or persistent monitoring.
- No external notification delivery or application network traffic.
- No active network scanning, probing, packet sending, or exploitation.
- No automatic remediation, firewall changes, process killing, file repair, or deletion.
- No PyPI publishing as part of this candidate.

Use observation commands only on systems and data you are authorized to inspect. Alerts
are investigation aids, not proof of compromise; zero alerts are not a security guarantee.
Doctor reports installation readiness, not endpoint security. See the
[security policy](../SECURITY.md) for the full scope.
