# SentinelLite AI Demo Guide

## Purpose

This guide provides a safe, professional flow for demonstrating the current SentinelLite AI `v0.1.0` prototype. The demonstration focuses on implemented defensive monitoring capabilities, transparent detection results, and the project's current limitations.

## Demo Environment

SentinelLite AI is designed for Linux endpoint monitoring. A local macOS development environment is supported for development checks, while Linux remains the target monitoring environment.

Ubuntu ARM64 VM validation is documented separately in the [Linux ARM64 validation notes](linux-validation.md).

## Prerequisites

Before starting the demonstration, ensure the following are available:

- Git
- Python 3
- A Python virtual environment
- Project dependencies installed from `requirements.txt`

## Setup

From the parent directory of the cloned repository, prepare the demo environment:

```bash
cd sentinellite-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
export PYTHONPATH=src
export PYTHONDONTWRITEBYTECODE=1
```

The environment variables allow the package to run directly from the source tree and prevent Python bytecode files from being created during the demonstration.

## Quality Checks

Begin by showing that the code passes linting and automated tests:

```bash
ruff check --no-cache src tests
pytest -p no:cacheprovider
```

These commands avoid creating Ruff and Pytest cache files in the project directory.

## Main CLI Status Demo

Display the application status and the availability of each monitoring module:

```bash
python -m sentinellite
```

Use this output to introduce the current prototype and distinguish implemented monitoring features from planned AI-assisted explanation.

## Authentication Scan Demo

Run the authentication pipeline against the included sample log:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
```

Explain that SentinelLite AI parses authentication activity, normalizes it into security events, applies transparent detection rules, assigns risk scores, and produces structured alerts.

## Process Scan Demo

Observe the processes currently running on the demo system:

```bash
python -m sentinellite scan-process
```

Process results depend on the live environment. A scan with no alerts means that no configured process rule matched the observed metadata; it is not a general security guarantee.

## Network Observation Demo

Observe active network connections:

```bash
python -m sentinellite scan-network
```

Network alerts can appear in a live VM because real network connections exist and may match investigation-focused rules. An alert identifies an observation for review; it does not by itself prove malicious activity.

## File Integrity Observation Demo

Observe one explicitly selected file:

```bash
python -m sentinellite scan-files README.md
```

Then demonstrate observation of multiple selected files:

```bash
python -m sentinellite scan-files README.md pyproject.toml
```

The current implementation records metadata and SHA-256 hashes for the supplied paths. It does not repair files or yet compare observations with a persistent baseline.

## JSON Reports

Scan reports are written into `reports/`. This directory is ignored by Git so locally generated demo output is not added to version control.

Each alert contains information suitable for review and later integration, including:

- Rule ID
- Risk level
- Score
- Message
- Evidence
- Recommendations

Open a generated JSON report after a scan to show how terminal summaries connect to structured, reviewable alert data.

## Safe Demo Notes

- SentinelLite AI is a defensive-only project.
- Its implemented collectors perform read-only observations.
- It does not perform port scanning.
- It does not send network packets.
- It does not repair or modify observed files.
- Alerts are investigation-focused and do not claim malware classification.
- AI-assisted alert explanation is planned but is not implemented yet.

Only demonstrate the project on systems and data that you are authorized to observe.

## Recommended Demo Flow

1. Show the README and introduce the defensive project scope.
2. Run the Ruff and Pytest quality checks.
3. Run the main CLI status command.
4. Run the authentication scan against the included sample log.
5. Run the process scan.
6. Run the network observation scan.
7. Run the file integrity observation scan.
8. Open a generated JSON report and explain its alert fields.
9. Explain the current limitations and next roadmap items.

## Current Limitations

- There is no persistent monitoring daemon yet.
- Baseline-backed file change detection is not implemented yet.
- AI-assisted explanation is not implemented yet.
- The project has a Linux-first design; macOS is supported as a development mode.

