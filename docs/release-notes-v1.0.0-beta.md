# SentinelLite AI v1.0.0-beta Release Notes

## Release Status

`v1.0.0-beta` is in development until it is formally released. It is not yet published as
a GitHub release, and it is not a production EDR release.

## Release Focus

This milestone freezes the existing CLI and data contracts for beta evaluation. It focuses
on release-surface cleanup, installation and package stability, a deterministic
fixture-first demonstration, clearer documentation of data contracts and safety
boundaries, and repeatable release validation. It is not a major feature milestone.

## Added

- Exact documentation for the established alert-report and notification-summary contracts
- A reusable release checklist covering source, package, CLI, fixture, schema, privacy,
  platform, PR, tag, and artifact gates
- Lightweight documentation checks for links, release status, safety wording, demo
  isolation, and contract statements
- Focused regression coverage proving bare status reflects an explicitly selected TOML config
- Entry-point coverage for equivalent console and module status behavior
- Improved version and normalized package-metadata assertions

## Changed

- The application version is now `1.0.0-beta`; Python package metadata normalizes it to
  `1.0.0b0`.
- CLI help, banner, status, and capability wording now describe an on-demand local defensive
  observation and report-review CLI rather than a resident agent.
- Bare status now reflects module and reporting settings from an explicitly selected TOML
  config. Command gating and configuration precedence are unchanged.
- README, demo, SECURITY, CONTRIBUTING, and Linux validation documentation now present the
  beta scope and limitations consistently.
- The primary demo is fixture-first and keeps generated configs, reports, and notification
  summaries in separate temporary locations outside the checkout.
- The unused stale root-level YAML file was removed. The packaged internal YAML resource
  remains available for installed status presentation and uses passive wording.
- CI now validates the beta display version and normalized wheel version on the supported
  Python floor and current validation version.

## Compatibility

- The default alert report retains exactly `report_id`, `report_type`, `generated_at`,
  `alert_count`, and `alerts` at the top level.
- No top-level `explanations` or alert-report `schema_version` field was added.
- Optional deterministic explanations remain nested inside individual alerts.
- The notification summary remains a separate schema with `schema_version` set to `1`.
- Notification export remains local, privacy-minimized, capped at 20 included alerts, and
  does not modify the source alert report.
- The `sentinellite` and `python -m sentinellite` entry styles remain supported.

## Validation Status

- Local M3 development tests and package checks: passed on Python 3.14 (597 tests)
- GitHub pull-request CI: pending
- Final macOS validation: pending M4
- Final Ubuntu ARM64 validation: pending M5
- GitHub tag and pre-release: not created

Validation results must not be recorded as final until they have run against the exact
candidate source state. The [release checklist](release-checklist.md) defines the required
gates, and platform evidence belongs in the [Linux validation notes](linux-validation.md)
after it is observed.

## Safety Scope

- On-demand local defensive observation and report review only
- No production EDR or comprehensive threat-detection claim
- No real AI or LLM execution; explanations are deterministic local templates
- No external notification delivery, provider integration, token behavior, or application
  network traffic
- No daemon, scheduler, background service, or persistent watcher
- No active network scanning, probing, packet sending, exploitation, or offensive behavior
- No automatic remediation, process termination, IP blocking, firewall changes, file repair,
  or deletion

Alerts and scores are investigation aids. They do not prove malware, compromise, or
unauthorized activity, and a zero-alert result is not a security guarantee.

## Known Limitations

- This beta is not published to PyPI.
- Authentication demonstration and release validation use bundled traditional-text
  fixtures, not real host authentication logs.
- Journald and compressed rotated logs are not supported.
- Process and network observations are environment-dependent one-shot snapshots.
- There is no automatic config or authentication-source discovery.
- There is no dashboard, database, report index, filter feature, ARM-SecNet integration, or
  automatic response behavior.
