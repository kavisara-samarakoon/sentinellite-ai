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
- 68 automated tests passing

## Security Scope

SentinelLite AI is a defensive cybersecurity project.

It is intended for:

- Linux endpoint monitoring
- authentication log analysis
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
- Normalized security event creation
- Rule-based detection
- Risk scoring
- JSON alert report generation
- Terminal-based scan summary

## Planned Features

- Network connection monitoring
- Open port monitoring
- File integrity monitoring
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

Both scan commands accept an optional output directory:

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

Example process scan summary:

```text
Processes found: 120
Security events created: 120
Detection matches: 1
Scored alerts: 1
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

## Example Detection Output

Example generated alerts:

```text
AUTH-001  MEDIUM (50)  Failed SSH login attempt
AUTH-002  INFO (20)    Successful SSH login
AUTH-003  LOW (45)     Sudo command usage
PROC-001  MEDIUM (60)  Temporary Path Process Execution
PROC-002  LOW (30)     High Process Resource Usage
PROC-003  LOW (40)     Suspicious Process Keyword
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

The current test suite contains 68 tests covering collectors, normalization, detection, scoring, reporting, pipelines, and CLI behavior.

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
```

## Current Detection Rules

| Rule ID | Name | Category | Base Score |
|---|---|---|---:|
| AUTH-001 | Failed SSH Login | Authentication | 50 |
| AUTH-002 | Successful SSH Login | Authentication | 20 |
| AUTH-003 | Sudo Command Usage | Privilege Usage | 45 |
| PROC-001 | Temporary Path Process Execution | Process Execution | 60 |
| PROC-002 | High Process Resource Usage | Resource Usage | 30 |
| PROC-003 | Suspicious Process Keyword | Process Behavior | 40 |

Process rules are investigation signals, not proof of compromise. High resource use and command-line keywords can have legitimate explanations and should be reviewed in context.

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

- Linux ARM64 testing
- Better CLI commands
- Network collector
- File integrity collector
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
