# SentinelLite AI

SentinelLite AI is a lightweight Linux endpoint detection and monitoring agent with planned AI-assisted alert analysis.

The project is a Python CLI tool focused on defensive Linux security monitoring. It collects security-relevant events, applies transparent detection rules, calculates risk levels, generates JSON reports, and presents local, deterministic guidance for investigating scored alerts. AI-assisted explanation remains a future capability and is not implemented.

## Current Status

Current milestone: `v0.7.0-alpha` (in development; not released)

The previous `v0.6.0-alpha` local report review milestone is published as a GitHub pre-release.

Current milestone status:

- CLI startup working
- Typed TOML configuration models, loading, and validation implemented
- `config-init` command implemented with safe overwrite refusal
- Explicit global `--config` loading implemented without automatic discovery
- Configurable reporting output and deterministic JSON explanation export implemented
- Configurable module gating and validated rule disabling implemented
- System information display working
- Authentication log collector implemented
- Normalized security event model implemented
- Detection engine implemented
- Authentication detection rules implemented
- Risk scoring engine implemented
- JSON alert reporter implemented
- Authentication scan pipeline implemented
- `scan-auth` CLI command working
- Process collector implemented
- Process observations normalized into security events
- Sensitive process command-line evidence redacted before reporting
- Process detection rules implemented
- Process scan pipeline implemented
- `scan-process` CLI command working
- Read-only network connection collector implemented
- Network observations normalized into security events
- Investigation-focused network detection rules implemented
- Network scan pipeline implemented
- `scan-network` CLI command working
- Read-only file integrity collector implemented for explicitly selected paths
- File integrity observations normalized into security events
- Investigation-focused file integrity detection rules implemented
- File integrity scan pipeline implemented
- `scan-files` CLI command working
- Versioned file integrity baseline model and JSON persistence implemented
- Baseline-backed file comparison, event normalization, detection, and risk scoring implemented
- File integrity baseline creation and scan pipelines implemented
- `baseline-files` and `scan-files-baseline` CLI commands working
- Deterministic explanation model and templates implemented for AUTH, PROC, NET, and FIM rules
- Local explanation generation and Rich terminal panels implemented
- Deterministic explanations displayed by scan commands when scored alerts exist
- Optional deterministic JSON explanation export implemented behind `--include-explanations`
- Default JSON alert reports retain the existing five-field top-level structure
- Read-only local report discovery and validation implemented
- `reports list` and `reports show REPORT_PATH` commands implemented
- Read-only discovery and validation of common Linux authentication log candidates implemented
- `auth-sources list` inventory command implemented without automatic scanning
- Clean authentication source errors for missing, unreadable, malformed, and unsupported paths
- Representative Ubuntu/Debian-style and RHEL/Fedora-style text fixtures implemented
- 531 automated tests passing

Baseline-backed file integrity monitoring is implemented and has been validated on Ubuntu ARM64. See the [Linux ARM64 validation notes](docs/linux-validation.md).

See [the demo guide](docs/demo-guide.md) for a suggested project demonstration flow.

See the [v0.1.0-alpha release notes](docs/release-notes-v0.1.0-alpha.md).

See the [v0.2.0-alpha release notes](docs/release-notes-v0.2.0-alpha.md) for the baseline-backed file integrity milestone.

See the [v0.3.0-alpha release notes](docs/release-notes-v0.3.0-alpha.md) for the deterministic CLI alert explanation milestone.

See the [v0.4.0-alpha release notes](docs/release-notes-v0.4.0-alpha.md) for the optional JSON explanation export milestone.

See the [v0.5.0-alpha release notes](docs/release-notes-v0.5.0-alpha.md) for the published explicit TOML configuration milestone.

See the [v0.6.0-alpha release notes](docs/release-notes-v0.6.0-alpha.md) for the published local report review milestone.

See the [v0.7.0-alpha release notes](docs/release-notes-v0.7.0-alpha.md) for the current Linux authentication log source compatibility milestone.

## Security Scope

SentinelLite AI is a defensive cybersecurity project.

It is intended for:

- Linux endpoint monitoring
- authentication log analysis
- read-only active network connection observation
- read-only observation of explicitly selected file paths
- baseline-backed file integrity monitoring for explicitly selected paths
- security learning
- safe lab testing
- defensive alerting
- SOC-style investigation practice
- structured JSON reporting
- local, deterministic, rule-based investigation guidance
- planned AI-assisted defensive explanation

It is not intended for:

- malware
- credential theft
- phishing
- backdoors
- unauthorized exploitation
- persistence payloads
- destructive automation
- harmful offensive activity

### Safety Boundaries

- File integrity monitoring uses explicit paths only and does not recursively scan directories.
- SentinelLite AI does not send packets or perform port scanning.
- The project contains no exploit code or malware functionality.
- It does not create, delete, repair, or modify monitored files.
- `baseline-files` writes only the explicitly requested baseline JSON file.
- `scan-files-baseline` writes only its JSON alert report.
- `reports list` and `reports show` read existing local reports without modifying them.
- Report review does not call an AI model, LLM, external API, or explanation service.
- `auth-sources list` performs local, read-only inventory and does not scan log contents or start `scan-auth`.
- Authentication scanning requires an explicit `scan-auth LOG_PATH`; candidate discovery never selects a source automatically.
- SentinelLite AI does not invoke `sudo` or modify log permissions or ownership.

## Implemented Features

- System information display
- Typed TOML configuration loading and validation
- Safe default TOML generation through `config-init`
- Explicit configuration selection through global `--config`
- Configurable report directories and JSON explanation export
- Configurable monitoring-module gating
- Validated detection-rule disabling by rule ID
- Authentication log parsing
- Failed SSH login detection
- Successful SSH login detection
- Sudo command usage detection
- Running process collection
- Process observation normalization
- Temporary-path process detection
- High process resource usage detection
- Suspicious process keyword detection
- Process command-line evidence redaction
- Active network connection collection
- Network observation normalization
- Investigation-focused network connection detection
- Selected file metadata and SHA-256 collection
- File integrity observation normalization
- Investigation-focused file integrity detection
- File integrity baseline creation and JSON persistence
- Baseline-backed file comparison and event normalization
- Baseline-backed file integrity detection rules
- Baseline-backed file integrity scan pipeline
- Normalized security event creation
- Rule-based detection
- Risk scoring
- JSON alert report generation
- Terminal-based scan summary
- Deterministic alert explanation model and rule templates
- Local explanation generation with generic fallback guidance
- Rich terminal explanation panels for scored alerts
- Optional nested JSON alert explanations requested with `--include-explanations`
- Read-only discovery and validation of existing local JSON alert reports
- Report directory listing and exact-path report summaries
- Read-only inventory of common Linux authentication log candidates
- Explicit authentication log selection with clean source validation errors
- Representative traditional Ubuntu/Debian-style and RHEL/Fedora-style fixture coverage

## Planned Features

- Improved detection rules
- AI-assisted alert explanation beyond the current deterministic template layer
- Additional Linux environment validation
- ARM-SecNet integration testing
- Local dashboard in a later version

## Development Environment

The tool can be developed on macOS, but the target monitoring environment is Linux.

Current development setup:

- macOS on Apple Silicon
- Python 3
- Virtual environment
- Typer CLI
- Rich terminal output
- Pytest testing
- Ruff linting

On macOS, SentinelLite AI runs in development mode. Full monitoring features will be tested inside Linux environments such as ARM64 Linux VMs.

## Installation

Clone the repository and enter the project folder:

```bash
git clone <repository-url>
cd sentinellite-ai
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

## Usage

Show SentinelLite AI status:

```bash
python -m sentinellite
```

### TOML Configuration

Create a default local configuration file without overwriting an existing file:

```bash
python -m sentinellite config-init
```

Use `--path` to select another location. Parent directories must already exist:

```bash
python -m sentinellite config-init --path configs/sentinellite.toml
```

Configuration is loaded only when explicitly selected with the global `--config` option:

```bash
python -m sentinellite --config sentinellite.toml scan-auth examples/auth_logs/sample_auth.log
```

SentinelLite AI does not automatically discover `sentinellite.toml` in the current directory. Without `--config`, the built-in defaults preserve the existing behavior: reports go to `reports/`, JSON explanation export is disabled, all monitoring modules are enabled, and all registered rules are active.

The generated file uses this structure:

```toml
config_version = 1

[reporting]
output_dir = "reports"
include_explanations = false

[modules]
authentication = true
process = true
network = true
file_integrity = true

[rules]
disabled_ids = []
```

`reporting.output_dir` selects the JSON alert report directory. A relative directory is resolved from the directory containing the selected config file. `reporting.include_explanations` controls nested deterministic explanation export; it does not change terminal explanation panels.

For reporting options, precedence is:

```text
explicit CLI option > selected TOML config > built-in default
```

The scan commands support `--include-explanations` and `--no-include-explanations`, allowing either config value to be explicitly overridden. `--output-dir` similarly overrides `reporting.output_dir`.

The `[modules]` values control their corresponding scan commands. Setting a module to `false` makes its command exit non-zero before collection, report writing, or baseline creation. Authentication controls `scan-auth`; process controls `scan-process`; network controls `scan-network`; and file integrity controls `scan-files`, `baseline-files`, and `scan-files-baseline`.

`rules.disabled_ids` accepts validated, case-sensitive rule IDs such as `AUTH-001` or `FIM-004`. Disabled rules are removed before detection, so their alerts and explanations are not generated. Unknown rule IDs cause configuration loading to fail cleanly.

### Linux Authentication Log Sources

List the common Linux authentication log candidates without scanning them:

```bash
python -m sentinellite auth-sources list
```

The inventory checks these candidate paths in deterministic order:

- `/var/log/auth.log` for Debian/Ubuntu-style systems
- `/var/log/secure` for RHEL/Fedora-style systems

These paths are candidates only, not guaranteed defaults. Their availability depends on the operating system and local logging configuration. `auth-sources list` does not recurse through `/var/log`, read or print log contents, start an authentication scan, invoke `sudo`, or modify file permissions or ownership.

Authentication scanning still requires an exact path selected by the user:

```bash
python -m sentinellite scan-auth LOG_PATH
```

Protected system logs should be selected only when the current account already has authorized read access. An authorized readable copy can be selected instead. SentinelLite AI does not elevate privileges or provide permission-changing behavior.

Two small, non-sensitive fixtures demonstrate the currently supported traditional text format:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log
python -m sentinellite scan-auth examples/auth_logs/sample_rhel_secure.log
```

The fixtures cover failed SSH password login, accepted SSH password login, sudo command, and ignored unrelated records. They do not imply support for every record produced by Ubuntu, Debian, RHEL, or Fedora. A scan with zero recognized events means that no currently supported record matched; it is not a general security guarantee.

Journald input and compressed rotated logs are not supported in v0.7. Authentication source selection is not part of the config schema, and there is no automatic source selection or `scan-auth --auto`. Authentication scans continue to produce the same five-field JSON report structure used by earlier milestones.

Scan a sample authentication log file:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
```

When the scan produces scored alerts, the existing alert table is followed by a `Deterministic Alert Explanations` section. Its local rule templates summarize why each rule matched, list possible causes, and recommend investigation steps. No explanation section is printed when there are no scored alerts.

Terminal explanation panels continue to appear whenever a scan produces scored alerts. To also export those deterministic explanations into the JSON alert report, pass the explicit `--include-explanations` option:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log --include-explanations
```

Without the option or an enabled config setting, JSON reports remain unchanged. With the option, or with `reporting.include_explanations = true`, each alert receives its own nested `explanation` object. Use `--no-include-explanations` to override an enabled config setting. The report does not add a top-level `explanations` field.

Scan the current running process list:

```bash
python -m sentinellite scan-process
```

Observe active network connections:

```bash
python -m sentinellite scan-network
```

Scan commands accept an optional output directory. For network observations, use:

```bash
python -m sentinellite scan-network --output-dir reports
```

Observe one explicitly selected file path:

```bash
python -m sentinellite scan-files README.md
```

Observe multiple explicitly selected paths:

```bash
python -m sentinellite scan-files README.md pyproject.toml
```

Use a specific report output directory:

```bash
python -m sentinellite scan-files README.md --output-dir reports
```

Create a trusted baseline from explicitly selected files:

```bash
python -m sentinellite baseline-files README.md pyproject.toml --baseline-path file-integrity-baseline.json
```

Later, scan the exact paths stored in the saved baseline:

```bash
python -m sentinellite scan-files-baseline --baseline-path file-integrity-baseline.json
```

Use a custom alert report directory for a baseline-backed scan:

```bash
python -m sentinellite scan-files-baseline --baseline-path file-integrity-baseline.json --output-dir reports
```

The baseline workflow starts by recording a trusted state for selected paths. A later scan observes those same paths and compares their current state with the saved baseline. Changed, missing, appeared, type-changed, and observation-error states become investigation signals. Unchanged files still produce comparison events but do not create alerts. The `not_in_baseline` comparison status is retained as context and is not currently an alert.

If a monitored file changes, the `FIM-004` alert is followed by a deterministic explanation panel with baseline-focused review guidance. The panel uses only the known rule template and evidence already present in the alert.

For example, process scan output can also be directed to `reports/`:

```bash
python -m sentinellite scan-process --output-dir reports
```

Example scan summary:

```text
Auth events found: 4
Security events created: 4
Detection matches: 4
Scored alerts: 4
JSON report: reports/alerts-...
```

Example network scan summary:

```text
Connections found: 42
Security events created: 42
Detection matches: 1
Scored alerts: 1
JSON report: reports/alerts-...
```

Example process scan summary:

```text
Processes found: 120
Security events created: 120
Detection matches: 1
Scored alerts: 1
JSON report: reports/alerts-...
```

Example file integrity scan summary:

```text
Files checked: 2
Security events created: 2
Detection matches: 0
Scored alerts: 0
JSON report: reports/alerts-...
```

## Process Monitoring Pipeline

The process scan follows the same defensive pipeline style as authentication scanning:

```text
Running process facts
→ process_observation SecurityEvent
→ conditional process detection rules
→ risk scoring
→ JSON alert report
```

Process command-line evidence is sanitized before it is added to a security event or report. Known password, token, API key, secret key, and URL credential values are replaced with `[REDACTED]`. SentinelLite AI observes and reports process activity; it does not kill, stop, block, or modify processes.

## Network Monitoring Pipeline

The network command uses a read-only observation pipeline:

```text
Active network connection metadata
→ network_connection_observation SecurityEvent
→ conservative network detection rules
→ risk scoring
→ JSON alert report
```

Network observations are based on active connection metadata available from the operating system. The rules provide investigation signals and do not classify a connection as malicious. SentinelLite AI does not perform port scanning, send packets, open sockets, or perform DNS lookups as part of this pipeline.

## File Integrity Monitoring Pipeline

The standard file integrity command uses a read-only observation pipeline for explicitly supplied paths:

```text
Selected path metadata and SHA-256 hash
→ file_integrity_observation SecurityEvent
→ conservative file integrity detection rules
→ risk scoring
→ JSON alert report
```

The baseline-backed workflow adds saved-state comparison without changing the collector's read-only behavior:

```text
Explicitly selected path observations
→ versioned baseline JSON
→ later observations of the exact baseline paths
→ file_integrity_baseline_comparison SecurityEvent
→ investigation-focused baseline detection rules
→ risk scoring
→ JSON alert report
```

The collector checks only paths supplied directly to `scan-files` or paths stored in an explicitly supplied baseline. It does not modify, create, delete, or repair monitored files, and it does not recursively scan directories. `baseline-files` writes only the baseline JSON file. `scan-files-baseline` writes only the JSON alert report. Baseline alerts identify changes for investigation and do not classify files as malware or automatically label activity as malicious.

## Example Detection Output

Example generated alerts:

```text
AUTH-001  MEDIUM (50)  Failed SSH login attempt
AUTH-002  INFO (20)    Successful SSH login
AUTH-003  LOW (45)     Sudo command usage
PROC-001  MEDIUM (60)  Temporary Path Process Execution
PROC-002  LOW (30)     High Process Resource Usage
PROC-003  LOW (40)     Suspicious Process Keyword
NET-001   MEDIUM (55)  Listening Service on Unusual Port
NET-002   LOW (35)     External Remote Connection
NET-003   LOW (40)     Suspicious Remote Port
FIM-001   MEDIUM (60)  Missing Monitored File
FIM-002   LOW (35)     File Integrity Check Error
FIM-003   INFO (20)    Directory Supplied for File Integrity Check
FIM-004   MEDIUM (70)  File Changed Compared With Baseline
FIM-005   MEDIUM (65)  File Missing Compared With Baseline
FIM-006   LOW (35)     File Appeared Compared With Baseline
FIM-007   MEDIUM (60)  File Type Changed Compared With Baseline
FIM-008   LOW (35)     File Integrity Baseline Comparison Error
```

## Deterministic Alert Explanations

When a scan produces scored alerts, the CLI builds an explanation from a local template keyed by the alert's rule ID. Each panel shows the rule, a plain-language summary, why the rule matched, possible causes, recommended investigation actions, confidence, and a small summary of evidence already present in the alert. Unknown rule IDs receive cautious generic guidance without invented rule-specific meaning.

This layer is deterministic and rule-based. It does not call an AI model, LLM, network API, or external explanation service. The guidance does not classify files or processes as malware, does not automatically claim a system is compromised, and does not perform response actions. AI-assisted explanation remains planned for future work.

## Reports

SentinelLite AI writes alert reports to the `reports/` directory by default. A selected TOML config can set `reporting.output_dir`, and an explicit `--output-dir` option takes precedence over that value.

Reports are generated as JSON files. Local reports are ignored by Git to avoid committing machine-specific scan output.

By default, reports retain the same five top-level fields: `report_id`, `report_type`, `generated_at`, `alert_count`, and `alerts`. Passing `--include-explanations` or enabling `reporting.include_explanations` adds a nested `explanation` object to each alert while leaving that top-level structure unchanged. No top-level `explanations` field is added.

Example report structure:

```json
{
  "report_id": "sentinellite-report-...",
  "report_type": "sentinellite_alert_report",
  "generated_at": "2026-08-26T15:12:48.437809+00:00",
  "alert_count": 4,
  "alerts": [
    {
      "rule_id": "AUTH-001",
      "risk_score": 50,
      "risk_level": "medium",
      "message": "Failed SSH login attempt",
      "explanation": {
        "rule_id": "AUTH-001",
        "title": "Failed SSH Login Attempt",
        "confidence": "medium"
      }
    }
  ]
}
```

The nested `explanation` shown above is present only in an opt-in report. Explanations are generated locally from deterministic rule templates and existing alert evidence.

### Reviewing Existing Reports

List compatible JSON alert reports in the default `reports/` directory:

```bash
python -m sentinellite reports list
```

Select another local report directory explicitly or through an explicitly selected config:

```bash
python -m sentinellite reports list --report-dir /tmp/sentinellite-reports
python -m sentinellite --config sentinellite.toml reports list
```

Directory selection for `reports list` follows this precedence:

```text
--report-dir > selected config reporting.output_dir > reports/
```

Show a safe summary of one report by its exact file path:

```bash
python -m sentinellite reports show /tmp/sentinellite-reports/alerts-....json
```

Both review commands are local and read-only. They do not write reports, change the report schema, create a database or persistent index, start a daemon, or call an AI model, LLM, or external API. `reports show` displays normalized metadata and compact alert fields without printing evidence or raw JSON by default. It reports only whether each stored explanation is present; it does not print the nested explanation body or regenerate explanations from current templates.

Malformed and incompatible reports fail with concise diagnostics and no raw-content dump. `reports list` keeps valid and invalid entries visible together, then exits non-zero when a directory contains invalid JSON report candidates. Report filters are not included in v0.6.

## Testing

The current test suite contains 531 tests covering configuration, collectors, authentication source discovery, Linux text fixtures, baseline models and persistence, normalization, detection, scoring, reporting, deterministic explanations, report review, pipelines, and CLI behavior.

Run all tests:

```bash
pytest
```

Run lint checks:

```bash
ruff check src tests
```

Recommended full local check:

```bash
ruff check src tests
pytest
python -m sentinellite
python -m sentinellite auth-sources list
python -m sentinellite config-init --path /tmp/sentinellite-v07.toml
python -m sentinellite --config /tmp/sentinellite-v07.toml scan-auth examples/auth_logs/sample_auth.log
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
python -m sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log
python -m sentinellite scan-auth examples/auth_logs/sample_rhel_secure.log
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log --include-explanations
python -m sentinellite reports list
python -m sentinellite reports show reports/alerts-....json
python -m sentinellite scan-process
python -m sentinellite scan-network
python -m sentinellite scan-files README.md
python -m sentinellite baseline-files README.md pyproject.toml --baseline-path file-integrity-baseline.json
python -m sentinellite scan-files-baseline --baseline-path file-integrity-baseline.json
```

## Current Detection Rules

| Rule ID | Name | Category | Severity | Base Score |
|---|---|---|---|---:|
| AUTH-001 | Failed SSH Login | Authentication | Medium | 50 |
| AUTH-002 | Successful SSH Login | Authentication | Low | 20 |
| AUTH-003 | Sudo Command Usage | Privilege Usage | Medium | 45 |
| PROC-001 | Temporary Path Process Execution | Process Execution | Medium | 60 |
| PROC-002 | High Process Resource Usage | Resource Usage | Low | 30 |
| PROC-003 | Suspicious Process Keyword | Process Behavior | Low | 40 |
| NET-001 | Listening Service on Unusual Port | Network Exposure | Medium | 55 |
| NET-002 | External Remote Connection | Network Connection | Low | 35 |
| NET-003 | Suspicious Remote Port | Network Behavior | Low | 40 |
| FIM-001 | Missing Monitored File | File Integrity | Medium | 60 |
| FIM-002 | File Integrity Check Error | File Integrity | Low | 35 |
| FIM-003 | Directory Supplied for File Integrity Check | File Integrity | Info | 20 |
| FIM-004 | File Changed Compared With Baseline | File Integrity Baseline | Medium | 70 |
| FIM-005 | File Missing Compared With Baseline | File Integrity Baseline | Medium | 65 |
| FIM-006 | File Appeared Compared With Baseline | File Integrity Baseline | Low | 35 |
| FIM-007 | File Type Changed Compared With Baseline | File Integrity Baseline | Medium | 60 |
| FIM-008 | File Integrity Baseline Comparison Error | File Integrity Baseline | Low | 35 |

Process rules are investigation signals, not proof of compromise. High resource use and command-line keywords can have legitimate explanations and should be reviewed in context.

Network rules are also investigation signals, not proof of compromise. Listening on an unusual port, connecting to an external address, or using a designated remote port may be legitimate and should be reviewed with process and endpoint context.

File integrity rules report current observation conditions such as an absent path, a collection error, or a directory supplied where a file was expected. Baseline rules additionally report changed, missing, appeared, type-changed, and current-error states compared with a saved baseline. Unchanged and `not_in_baseline` statuses do not produce alerts. These rules provide investigation signals; they do not indicate malware, prove compromise, or establish that a change was unauthorized.

## Risk Levels

| Level | Minimum Score |
|---|---:|
| Info | 0 |
| Low | 25 |
| Medium | 50 |
| High | 75 |
| Critical | 90 |

## Roadmap

### Version 0.1

- Project foundation
- Authentication log scanning
- Detection rules
- Risk scoring
- JSON reports
- CLI scan command
- Unit tests

### Version 0.2

- Process collector
- Process event normalization and command-line redaction
- Conditional process detection rules
- Process scan pipeline and CLI command

### Version 0.3

- Read-only network connection collector
- Network event normalization and conservative detection rules
- Network scan pipeline and CLI command
- Read-only file integrity collector for explicitly selected paths
- File integrity event normalization and conservative detection rules
- File integrity scan pipeline and CLI command
- Linux ARM64 testing
- Better CLI commands
- Baseline-backed file integrity creation, comparison, detection, reporting, and CLI workflow
- Deterministic, local alert explanations in CLI output
- Screenshots and demo evidence

### Version 0.4

- Optional deterministic explanation export inside JSON alerts
- Explicit `--include-explanations` support across alert-producing scan commands
- Backward-compatible default JSON reports
- CI validation for nested opt-in explanation objects

### Version 0.5

- Typed local `sentinellite.toml` configuration
- Safe `config-init` command
- Explicit global `--config` selection without automatic discovery
- Configurable reporting directory and JSON explanation export
- Validated rule disabling through `rules.disabled_ids`
- Monitoring-module gating before collection and report or baseline writing

### Version 0.6

- Read-only discovery and validation of local SentinelLite JSON alert reports
- `reports list` with explicit, configured, and default directory selection
- `reports show REPORT_PATH` summaries for exact report paths
- Clean malformed and incompatible report diagnostics
- Backward-compatible v0.5 JSON report schema
- No filters, database, persistent index, daemon, external API, AI, or LLM behavior

### Version 0.7

- Read-only inventory of `/var/log/auth.log` and `/var/log/secure` as common candidates
- Explicit `scan-auth LOG_PATH` selection retained without automatic defaults
- Clean errors for missing, unreadable, malformed, and unsupported authentication sources
- Representative Ubuntu/Debian-style and RHEL/Fedora-style traditional text fixtures
- JSON report and v0.6 report review compatibility validation
- No journald, compressed rotation, config source selection, automatic scanning, external API, AI, or LLM behavior

### Version 1.0

- Stable Linux endpoint monitoring CLI
- Tested on ARM64 Linux VM
- Documented integration with ARM-SecNet
- GitHub-ready release

## Security Notice

SentinelLite AI follows a monitor-first approach.

Version 1 should monitor, alert, report, explain, and recommend. It should not automatically kill processes, block IP addresses, delete files, or modify firewall rules.

## Author

Kavisara Samarakoon  
Computer Networks Student, NSBM Green University  
External BIT Student, University of Moratuwa  
Career Direction: Cybersecurity Analyst and Network Engineer
