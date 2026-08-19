# SentinelLite AI

SentinelLite AI is a lightweight Linux endpoint detection and monitoring agent with planned AI-assisted alert analysis.

The project starts as a Python CLI tool focused on defensive Linux security monitoring. It collects security-relevant events, applies transparent detection rules, calculates risk levels, generates JSON reports, and later provides human-readable defensive explanations.

## Current Status

Version: `v0.1.0`

Current prototype status:

- CLI startup working
- Configuration loader working
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
- 207 automated tests passing

See [Linux ARM64 validation notes](docs/linux-validation.md).

See [the demo guide](docs/demo-guide.md) for a suggested project demonstration flow.

See the [v0.1.0-alpha release notes](docs/release-notes-v0.1.0-alpha.md).

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

## Implemented Features

- System information display
- YAML configuration loading
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

## Planned Features

- Improved detection rules
- AI-assisted alert explanation
- Linux ARM64 VM testing
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

Scan a sample authentication log file:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
```

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

## Reports

SentinelLite AI writes alert reports to the `reports/` directory.

Reports are generated as JSON files. Local reports are ignored by Git to avoid committing machine-specific scan output.

Example report structure:

```json
{
  "report_type": "sentinellite_alert_report",
  "alert_count": 4,
  "alerts": [
    {
      "rule_id": "AUTH-001",
      "risk_score": 50,
      "risk_level": "medium",
      "message": "Failed SSH login attempt"
    }
  ]
}
```

## Testing

The current test suite contains 207 tests covering collectors, baseline models and persistence, normalization, detection, scoring, reporting, pipelines, and CLI behavior.

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
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
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
- AI-assisted alert explanation
- Screenshots and demo evidence

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
