# SentinelLite AI v0.5.0-alpha Release Notes

## Release Status

`v0.5.0-alpha` is an in-development alpha milestone until it is formally released. It is intended for controlled demonstration, authorized defensive security learning, and portfolio review. It is not presented as a production EDR release.

## Release Focus

This milestone adds explicit local TOML configuration, safe default-config creation, reporting configuration, validated rule disabling, and monitoring-module gating. Existing behavior remains the default when no config is selected.

## Added

- Frozen typed configuration models for reporting, modules, and rule control
- Standard-library TOML loading and strict validation
- `config-init` for exclusive creation of a default `sentinellite.toml`
- Global `--config` selection for an exact config path
- Configurable `reporting.output_dir`
- Configurable `reporting.include_explanations`
- Dual `--include-explanations` and `--no-include-explanations` CLI overrides
- Validated, case-sensitive `rules.disabled_ids` selection
- Module gating for authentication, process, network, and file-integrity commands
- CI smoke coverage for config creation, config-driven reporting, JSON compatibility, and disabled-module behavior

## Changed

- Scan commands resolve reporting options using this precedence:

  ```text
  explicit CLI option > selected TOML config > built-in default
  ```

- Disabled rules are removed before detection, so their alerts and explanations are not generated.
- Disabled modules exit non-zero before collection, alert-report writing, or baseline creation.
- The CLI version display now reports `SentinelLite AI v0.5.0-alpha`.

## Validation

- Automated Ruff, Pytest, CLI, and CI smoke validation is defined for this milestone.
- macOS development validation: pending
- Ubuntu ARM64 validation: pending

Validation status will be updated only after the corresponding checks are completed. These release notes do not indicate that a GitHub release has been published.

## Safety Scope

- Defensive, investigation-focused endpoint observation only
- Local deterministic rule matching and explanation templates
- No real AI or LLM execution
- No external API or explanation service calls
- No malware classification or confirmed-compromise claims
- No automatic process termination, IP blocking, file repair, deletion, or firewall changes
- No automatic config-file discovery

## Config Behavior

Configuration is used only when an exact file is supplied through global `--config`. Missing values inherit built-in defaults. Relative report directories resolve from the selected config file's directory.

Unknown config keys, invalid types, unsupported config versions, unknown rule IDs, duplicate disabled rule IDs, malformed TOML, and missing files fail cleanly before a scan pipeline runs.

Module mappings are:

- `authentication`: `scan-auth`
- `process`: `scan-process`
- `network`: `scan-network`
- `file_integrity`: `scan-files`, `baseline-files`, and `scan-files-baseline`

Without `--config`, all modules and registered rules remain active, reports use `reports/`, and JSON explanation export remains disabled.

## JSON Reporting Compatibility

The JSON report retains exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

Config-driven or CLI-driven explanation export adds one nested `explanation` object to each generated alert. It does not add a top-level `explanations` field. Default reports remain unchanged.

## Known Limitations

- Not a production EDR
- No persistent monitoring daemon
- No dashboard
- Config files require explicit `--config` selection
- No command-line override for enabling a module disabled by config
- Rule control supports disabling registered rules rather than defining new rules
- Real AI-assisted or LLM-based explanation is not implemented
- macOS and Ubuntu ARM64 validation remain pending for this milestone

## Author

Kavisara Samarakoon
