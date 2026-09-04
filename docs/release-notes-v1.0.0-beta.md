# SentinelLite AI v1.0.0-beta Release Notes

## Release Status

`v1.0.0-beta` is published as a GitHub pre-release. The immutable tag
`v1.0.0-beta` points to commit `6b73ebe22e70fec1cf91206064daa9cca24e596f`.
[SentinelLite AI v1.0.0-beta](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.0.0-beta)
was published on September 4, 2026 at `19:48:10 UTC`. It is not a production EDR release.
This published status supersedes the earlier statements that `v1.0.0-beta` is in development
and not yet published as a GitHub release; those statements are no longer current.

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

## Validation and Publication Status

- Local M3 development tests and package checks: passed on Python 3.14 (597 tests)
- Final macOS candidate validation: completed at `c873330` on Apple Silicon `arm64` with
  Python `3.14.6` and 597 passing tests
- Final Ubuntu ARM64 candidate validation: completed at `c873330` on `aarch64` with Python
  `3.14.4` and 597 passing tests
- Pull request #9: reviewed and merged
- GitHub CI: passed on Python 3.11 and Python 3.14
- Merge to `main`: completed
- Final tag: `v1.0.0-beta`, pointing to
  `6b73ebe22e70fec1cf91206064daa9cca24e596f`
- Final tagged artifacts: rebuilt and validated from the tagged release commit
- Final SHA-256 checksums: generated
- GitHub pre-release publication: completed

The completed candidate runs include entry-point, fixture, report, notification, schema,
privacy, package, and isolated-install validation. Their candidate artifact hashes are
recorded in the [platform validation notes](linux-validation.md), but they are not the final
official tagged-release artifact hashes below.

## Final Tagged-Release Artifacts

The published GitHub pre-release contains:

1. `sentinellite_ai-1.0.0b0-py3-none-any.whl`
2. `sentinellite_ai-1.0.0b0.tar.gz`
3. `SHA256SUMS.txt`

Official final release artifact SHA-256 values:

- Wheel: `b2524b0f969c6685f18f5218376ae2db76dcfd35898281cc68a106f53f7af082`
- Source distribution: `ceda8458c1afb9cec640ba9527039805564edc8d6fe1b358fb822495d9b2c990`
- `SHA256SUMS.txt` GitHub asset digest:
  `d72c2f985545bb72bc8273984ea26ed31015acca04e4aae70c52469cd3c613a9`

These are the official hashes for the assets attached to the immutable `v1.0.0-beta`
GitHub pre-release. They supersede the earlier macOS and Ubuntu candidate-validation hashes
for release-download verification; those earlier hashes remain historical validation-run
evidence only.

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
