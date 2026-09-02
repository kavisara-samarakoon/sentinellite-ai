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

- The current macOS development validation passed with 588 tests before the M5 documentation milestone.
- Final macOS release validation is pending.
- Final Ubuntu ARM64 release validation is pending.
- GitHub pull-request CI for the completed v0.9 milestone is pending.

These statements do not claim a published release or final platform validation. The validation contract includes editable installation, dependency checking, Ruff, Pytest, both CLI entry styles, wheel construction, and wheel metadata, license, entry-point, and packaged-resource checks.

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
