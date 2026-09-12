# SentinelLite AI v1.1.0-beta Release Notes

## Release Status

`v1.1.0-beta` is published as a GitHub pre-release:
[SentinelLite AI v1.1.0-beta](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.1.0-beta).
It was published at `2026-09-12T01:22:37Z`. The immutable tag `v1.1.0-beta` points to the
merged main commit `e816a0a40efa24e98ccf3616cefe510d252c3656`.
The previous published release was `v1.0.0-beta`. SentinelLite AI is not on PyPI yet.

The CLI display version is `SentinelLite AI v1.1.0-beta`. Python package metadata normalizes
the version to `1.1.0b0`, derived from the single source `sentinellite.__version__`.

## Release Focus

This release improves public usability: helping a new user verify a local installation,
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

Install the published `v1.1.0-beta` wheel or current source from `main`. The wheel includes
`doctor` and `demo`. The previous `v1.0.0-beta` wheel did not include these commands and
remains unchanged.

- Python 3.11 or newer is required. Console and module entry points remain supported.
- `doctor` and `demo` support `--output-dir`; selected TOML reporting settings remain
  available. Demo uses built-in rules and can store deterministic explanations.
- Doctor failures exit with code 1. Passes and warnings exit with code 0. Non-Linux systems
  receive a warning because endpoint observation targets Linux.
- Typer and Rich must be installed for the CLI, including doctor, to start. Missing
  `psutil` or PyYAML can be reported by doctor without preventing CLI startup.
- Existing scan and report-review behavior remains unchanged. New runtime behavior is
  limited to the `doctor`/`demo` onboarding commands and the version display.
- The JSON report schema is unchanged: the top-level fields remain `report_id`,
  `report_type`, `generated_at`, `alert_count`, and `alerts`. Optional explanations remain
  nested in individual alerts. The separate local notification-summary schema is unchanged.

## Validation

Local validation passed with 620 automated tests covering CLI commands, local installation checks,
synthetic demo boundaries, configuration, collectors, detection, scoring, reports,
explanations, entry points and packaging. Release preparation also passed dependency checks,
both version entry points, Ruff, a wheel/source build and `git diff --check`.

This guide and the automated suite do not establish completed ARM-SecNet runtime
validation for this release. Historical `v1.0.0-beta` platform results remain historical
evidence and do not establish Ubuntu ARM64 lab validation for `v1.1.0-beta`.

## Final Published Release Assets

The GitHub pre-release contains:

- `sentinellite_ai-1.1.0b0-py3-none-any.whl`
- `sentinellite_ai-1.1.0b0.tar.gz`
- `SHA256SUMS.txt`

Final SHA-256 values for the published assets:

- Wheel: `5ffd87da08d63d9872b17f5b6bd496f7a6da3149ba8e5076cb2abcbf8a356dc6`
- Source distribution: `8ccd7afa9e100edaca912f967dc339e80a5492d582383596dd61ae5da529a85d`
- `SHA256SUMS.txt` GitHub asset digest:
  `f5d6659a725301f180f65f06e7dc4016d7bbc141c6c27eb8954da5f3020f0be6`

These values identify the assets published with the immutable `v1.1.0-beta` tag. This
post-release documentation update does not replace those assets or move the release tag.

## Defensive-Only Scope

This is not a production EDR release. SentinelLite AI is not antivirus, a SIEM/SOC platform,
a malware remover, or an enterprise security platform. It is not real AI/LLM-powered.
Local checks and synthetic demonstrations do not establish production readiness.

- No real AI or LLM execution; explanations use deterministic local templates.
- No daemon, scheduler, background service, or persistent monitoring.
- No external notification delivery or application network traffic.
- No active network scanning, probing, packet sending, or exploitation.
- No automatic remediation, firewall changes, process killing, file repair, or deletion.
- No PyPI publishing as part of this release.

Use observation commands only on systems and data you are authorized to inspect. Alerts
are investigation aids, not proof of compromise; zero alerts are not a security guarantee.
Doctor reports installation readiness, not endpoint security. See the
[security policy](../SECURITY.md) for the full scope.
