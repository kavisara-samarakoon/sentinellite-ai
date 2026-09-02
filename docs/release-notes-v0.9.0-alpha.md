# SentinelLite AI v0.9.0-alpha Release Notes

## Release Status

`v0.9.0-alpha` is in development until it is formally released. It is not yet published as a GitHub release, and it is not a production EDR release.

## Release Focus

This milestone focuses on package, installation, and CLI usability readiness for local development, validation, and fixture-based demonstrations.

## Added

- Installable Python project metadata for `sentinellite-ai`
- Explicit runtime dependency declarations and a `dev` optional dependency group
- A single version source in `sentinellite.__version__`
- A packaged default configuration resource that works outside the repository working directory
- The installed `sentinellite` console command
- A side-effect-free global `--version` option shared by console and module entry points
- CI checks that exercise the installed editable package
- Wheel metadata, entry-point, packaged-resource, and isolated-install smoke validation
- The standard MIT License, with accurate package license metadata

## Changed

- `requirements.txt` now delegates to the development extra as an editable-install compatibility shim.
- CI installation no longer relies on a global `PYTHONPATH=src` setting.
- User and demo documentation now presents the installed `sentinellite` command as the primary flow while retaining `python -m sentinellite` support.

## Validation

### GitHub PR Validation

PR #8 passed the `CI/Packaging, Ruff, and Pytest` workflow for both `push` and `pull_request`. The workflow validated editable installation, `pip check`, console and module entry points, Ruff, Pytest, a fixture scan, alert-report and notification compatibility, wheel metadata and packaged resources, and an isolated wheel smoke test.

### macOS Development Validation

Final macOS development validation passed with Python 3.14.6:

- Editable installation and `pip check`: passed
- `sentinellite --version` and `python -m sentinellite --version`: passed
- Wheel build and wheel license/resource smoke: passed
- Ruff: passed
- Pytest: 588 passed
- `git diff --check`: passed
- Generated `dist/`, `build/`, and egg-info artifacts: removed after validation

### Ubuntu ARM64 Validation

Final Ubuntu ARM64 validation passed on Linux `aarch64` with Python 3.14.4, Ruff 0.16.3, and Pytest 9.1.1:

- Editable installation and `pip check`: passed
- Console and module version commands: passed
- Bare console and module status from `/tmp`: passed
- Ruff: passed
- Pytest: 588 passed
- `auth-sources list`: passed; `/var/log/auth.log` was inventoried as available and `/var/log/secure` as missing
- Bundled Ubuntu authentication fixture scan: 3 authentication events and 3 alerts
- `reports list` and `reports show`: passed
- Notification export: 3 included alerts and 0 omitted alerts
- Notification privacy and separate-schema compatibility: passed
- Existing five-field alert-report schema and report-review compatibility: passed
- Wheel build, metadata, resource, MIT License, and console entry-point validation: passed
- Final worktree: clean

The available `/var/log/auth.log` was inventoried only; it was not read or scanned. Scan behavior was validated with `examples/auth_logs/sample_ubuntu_auth.log`. The original generated alert report retained exactly `report_id`, `report_type`, `generated_at`, `alert_count`, and `alerts` at the top level, with no top-level `explanations` field. The notification summary retained its independent schema.

These results validate the in-development milestone; they do not claim a published GitHub release or production readiness. Detailed Ubuntu results are recorded in the [Linux ARM64 validation notes](linux-validation.md).

## Installation and Entry-Point Behavior

An editable install from a cloned repository provides the primary `sentinellite` command. `python -m sentinellite` remains supported and uses the same CLI callable and command tree. Both entry styles read the version from the same package value, and `--version` exits without loading configuration or running monitoring behavior.

The default YAML configuration is included inside the package, so normal installed execution does not depend on the process working directory. Example fixture demonstrations still require a cloned repository because their input paths are repository files.

## Safety Scope

- Defensive, investigation-focused local endpoint observation only
- No external delivery, external API calls, or application network traffic
- No email, Slack, Discord, webhook, SMS, provider, or token behavior
- No real AI or LLM execution
- No daemon or background monitoring
- No automatic remediation, process termination, IP blocking, firewall changes, or file deletion and repair
- No production EDR claim and no claim that an alert proves malware or compromise
- No detection, scoring, alert-report schema, or notification schema change in this packaging milestone

## Known Limitations

- The package is not published to PyPI.
- No shell installer, Homebrew package, Docker image, or system service is provided.
- Example fixture demos require a cloned repository.
- The console command must be installed into an active virtual environment or another directory available on `PATH`.
- v0.9 packaging improves local installation readiness; it does not provide production deployment readiness.
- External notification sending and provider integrations are not implemented.
- Real AI-assisted or LLM-based execution is not implemented.

## Author

Kavisara Samarakoon
