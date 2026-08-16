# SentinelLite AI

SentinelLite AI is a lightweight Linux endpoint detection and monitoring agent with AI-assisted alert analysis.

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
- Unit tests passing

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
- AI-assisted defensive explanation

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
- Normalized security event creation
- Rule-based detection
- Risk scoring
- JSON alert report generation
- Terminal-based scan summary

## Planned Features

- Process monitoring
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

Example scan summary:

```text
Auth events found: 4
Security events created: 4
Detection matches: 4
Scored alerts: 4
JSON report: reports/alerts-...
```

## Example Detection Output

Example generated alerts:

```text
AUTH-001  MEDIUM (50)  Failed SSH login attempt
AUTH-002  INFO (20)    Successful SSH login
AUTH-003  LOW (45)     Sudo command usage
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
```

## Current Detection Rules

| Rule ID | Name | Category | Base Score |
|---|---|---|---:|
| AUTH-001 | Failed SSH Login | Authentication | 50 |
| AUTH-002 | Successful SSH Login | Authentication | 20 |
| AUTH-003 | Sudo Command Usage | Privilege Usage | 45 |

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
- Network collector
- File integrity collector
- Improved detection rules

### Version 0.3

- Linux ARM64 testing
- Better CLI commands
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