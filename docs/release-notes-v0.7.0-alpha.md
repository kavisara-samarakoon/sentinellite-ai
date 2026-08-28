# SentinelLite AI v0.7.0-alpha Release Notes

## Release Status

`v0.7.0-alpha` is an in-development alpha milestone until it is formally released.

## Release Focus

This milestone improves Linux authentication log source compatibility while preserving explicit user selection. It adds local, read-only inventory for common authentication log file candidates and representative traditional text fixture validation without changing detection or report behavior.

## Added

- Frozen, typed authentication log candidate and inventory entry models
- Deterministic candidate inventory for `/var/log/auth.log` and `/var/log/secure`
- Read-only validation for missing, unreadable, malformed UTF-8, and unsupported authentication sources
- `auth-sources list` with literal terminal rendering and concise candidate diagnostics
- Representative Ubuntu/Debian-style traditional text fixture
- Representative RHEL/Fedora-style traditional text fixture
- Collector, pipeline, CLI, JSON compatibility, report review, and CI smoke coverage for both fixtures

## Changed

- The CLI version display now reports `SentinelLite AI v0.7.0-alpha`.
- Expected `scan-auth` source failures now exit non-zero with clean messages and no traceback.
- The README and demo flow now distinguish source inventory from explicit authentication scanning.
- `scan-auth LOG_PATH` remains explicit and backward-compatible.
- No detection rule, risk scoring, config schema, dependency, JSON writer, or report review behavior changed.

## Validation

- Automated Ruff, Pytest, CLI, fixture, JSON compatibility, report review, and CI smoke validation is defined.
- macOS development validation: pending
- Ubuntu ARM64 validation: pending
- Real authorized `/var/log/auth.log` validation: pending
- No Fedora or RHEL runtime validation is claimed yet; the committed RHEL/Fedora-style input is a representative fixture only.

## Safety Scope

- Defensive, investigation-focused endpoint observation only
- Local, read-only authentication source inventory
- Explicit authentication log path selection only
- No automatic scanning or source selection
- No `sudo` invocation or permission or ownership modification
- No real AI or LLM execution
- No external API calls
- No malware classification or confirmed-compromise claims
- No production EDR claim
- No automatic process termination, IP blocking, file repair, deletion, or firewall changes
- No database, persistent source index, dashboard, or monitoring daemon change

## Auth Source Behavior

`auth-sources list` checks two common candidates in deterministic order:

- `/var/log/auth.log` labeled `debian_ubuntu`
- `/var/log/secure` labeled `rhel_fedora`

These paths are candidates only, not guaranteed defaults. The command reports whether each candidate is available, missing, unreadable, or unsupported. It does not recurse through `/var/log`, read or print log contents, invoke `sudo`, alter permissions, choose a source, or run `scan-auth`.

Authentication scanning continues to require:

```text
scan-auth LOG_PATH
```

Protected logs require existing authorized read access or an authorized readable copy. A scan with zero recognized events means that no supported record matched; it is not a general security guarantee.

## JSON Reporting Compatibility

The JSON writer still produces exactly these five top-level fields:

- `report_id`
- `report_type`
- `generated_at`
- `alert_count`
- `alerts`

Authentication source family, inventory status, and candidate metadata are not added to reports. Reports generated from both compatibility fixtures are accepted by the existing v0.6 report review module.

## Known Limitations

- Candidate availability under `/var/log` is system-dependent.
- Automatic authentication source selection is not implemented.
- `scan-auth --auto` is not implemented.
- Authentication source selection is not available through config.
- Journald input is not supported in v0.7.
- Compressed rotated authentication logs are not supported in v0.7.
- The parser supports selected traditional failed SSH password, accepted SSH password, and sudo records; it does not claim support for every distribution record.
- Real authorized `/var/log/auth.log`, Ubuntu ARM64 v0.7, and RHEL/Fedora runtime validation remain pending.
- There is no database, persistent source index, dashboard, or daemon.
- Real AI-assisted or LLM-based explanation is not implemented.

## Author

Kavisara Samarakoon
