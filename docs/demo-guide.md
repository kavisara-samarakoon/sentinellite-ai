# SentinelLite AI Demo Guide

## Purpose

This guide provides a safe, professional flow for demonstrating the SentinelLite AI `v0.8.0-alpha` in-development milestone. The demonstration focuses on explicit local TOML configuration, Linux authentication log source compatibility, implemented defensive monitoring, transparent detection results, local deterministic alert explanations, optional JSON explanation export, read-only local report review, privacy-minimized local notification summary export, and the project's current limitations.

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

Use this output to introduce the current milestone and distinguish implemented deterministic explanation templates from future AI-assisted explanation.

## TOML Configuration Demo

Create the default configuration in the current directory:

```bash
python -m sentinellite config-init
```

Inspect `sentinellite.toml` with a local text editor. The file contains reporting settings, module switches, and a list of disabled rule IDs. `config-init` refuses to overwrite an existing file, and SentinelLite AI does not automatically discover this file.

Run the authentication scan with the config explicitly selected:

```bash
python -m sentinellite --config sentinellite.toml scan-auth examples/auth_logs/sample_auth.log
```

To demonstrate a config-selected report directory and nested JSON explanations, edit the reporting table:

```toml
[reporting]
output_dir = "demo-reports"
include_explanations = true
```

Run the same explicit-config command again. The report is written beneath `demo-reports/`, and each generated alert contains a nested deterministic `explanation` object. An explicit `--output-dir`, `--include-explanations`, or `--no-include-explanations` option overrides the corresponding config value.

To demonstrate rule control, disable the failed-login rule:

```toml
[rules]
disabled_ids = ["AUTH-001"]
```

Run the authentication command again. `AUTH-001` alerts and their explanations are absent, while other matching authentication rules remain active. Rule IDs are validated and case-sensitive; invalid IDs cause a clean configuration error before the scan runs.

To demonstrate module gating, disable process monitoring:

```toml
[modules]
authentication = true
process = false
network = true
file_integrity = true
```

Then run:

```bash
python -m sentinellite --config sentinellite.toml scan-process
```

The command exits non-zero with `Process monitoring is disabled by configuration.` No process collection or alert report writing occurs. Restore `process = true` before continuing with the process demo.

## Authentication Scan Demo

Run the authentication pipeline against the included sample log:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
```

Explain that SentinelLite AI parses authentication activity, normalizes it into security events, applies transparent detection rules, assigns risk scores, and produces structured alerts.

### Linux Authentication Log Source Compatibility Demo

Inventory the two common Linux authentication log candidates:

```bash
python -m sentinellite auth-sources list
```

Explain that the command checks `/var/log/auth.log` as a Debian/Ubuntu-style candidate and `/var/log/secure` as a RHEL/Fedora-style candidate. These are candidates only, not guaranteed defaults. The inventory is local and read-only: it does not read or print log contents, recurse through `/var/log`, select a source, or start a scan automatically.

Run the bundled Ubuntu/Debian-style traditional text fixture into a temporary report directory:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log --output-dir /tmp/sentinellite-v07-ubuntu-auth
```

Run the bundled RHEL/Fedora-style traditional text fixture into a separate temporary report directory:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_rhel_secure.log --output-dir /tmp/sentinellite-v07-rhel-secure
```

These fixtures demonstrate the currently supported failed SSH password, accepted SSH password, and sudo record shapes. They are representative fixtures, not claims that every distribution record format is supported or that RHEL/Fedora runtime validation has occurred.

List the Ubuntu fixture report:

```bash
python -m sentinellite reports list --report-dir /tmp/sentinellite-v07-ubuntu-auth
```

Then resolve its exact path and review it:

```bash
REPORT_PATH="$(python - <<'PY'
from pathlib import Path

reports = sorted(Path("/tmp/sentinellite-v07-ubuntu-auth").glob("*.json"))
assert len(reports) == 1, reports
print(reports[0])
PY
)"
python -m sentinellite reports show "$REPORT_PATH"
```

For real system logs, keep `scan-auth LOG_PATH` explicit and select a path only when the current account already has authorized read access, or use an authorized readable copy. Do not change permissions or invoke broad privilege elevation for this demonstration.

### Deterministic Alert Explanation Demo

The included authentication sample produces scored alerts, so the same command is a stable explanation demonstration:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log
```

After the existing alert table, review the `Deterministic Alert Explanations` panels. Explain that each panel comes from a local rule template and uses evidence already present in the alert. Explanation panels appear only when scored alerts exist; a no-alert scan does not print an empty explanation section.

### Optional JSON Explanation Export Demo

First, write a default report without JSON explanations:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log --output-dir /tmp/sentinellite-default-report
```

Then write an opt-in report with nested deterministic explanations:

```bash
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log --output-dir /tmp/sentinellite-explained-report --include-explanations
```

Use the Python standard library to verify both reports:

```bash
python - <<'PY'
import json
from pathlib import Path

default_path = max(Path("/tmp/sentinellite-default-report").glob("*.json"))
explained_path = max(Path("/tmp/sentinellite-explained-report").glob("*.json"))

default_report = json.loads(default_path.read_text(encoding="utf-8"))
explained_report = json.loads(explained_path.read_text(encoding="utf-8"))
expected_keys = {
    "report_id",
    "report_type",
    "generated_at",
    "alert_count",
    "alerts",
}

assert set(default_report) == expected_keys
assert set(explained_report) == expected_keys
assert default_report["alerts"]
assert explained_report["alerts"]
assert all("explanation" not in alert for alert in default_report["alerts"])
assert all("explanation" in alert for alert in explained_report["alerts"])
assert "explanations" not in default_report
assert "explanations" not in explained_report
print("Default and opt-in JSON reports verified.")
PY
```

Both scans still display terminal explanation panels when scored alerts exist. The flag controls only whether explanation objects are also exported inside the JSON alerts. A selected config can provide the same setting through `reporting.include_explanations`, while the explicit CLI flag takes precedence.

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

The current implementation records metadata and SHA-256 hashes for the supplied paths. It does not repair or modify files. Persistent comparison is available through the separate baseline workflow below.

## Baseline-Backed File Integrity Demo

Create a baseline for explicitly selected files:

```bash
python -m sentinellite baseline-files README.md pyproject.toml --baseline-path file-integrity-baseline.json
```

Scan the paths recorded in that baseline:

```bash
python -m sentinellite scan-files-baseline --baseline-path file-integrity-baseline.json
```

For a controlled changed-file demonstration, use a temporary test file that you are authorized to modify, create its baseline, change its contents, and scan the baseline again. A changed state can generate `FIM-004 File Changed Compared With Baseline`, followed by a deterministic panel that recommends confirming whether the change was expected and reviewing relevant update, deployment, and user context. The alert is an investigation signal, not an automatic classification of the change.

## JSON Reports

Scan reports are written into `reports/`. This directory is ignored by Git so locally generated demo output is not added to version control.

Each alert contains information suitable for review and later integration, including:

- Rule ID
- Risk level
- Score
- Message
- Evidence
- Recommendations

Open a generated JSON report after a scan to show how terminal summaries connect to structured, reviewable alert data. Default reports contain no explanation objects. Reports created with `--include-explanations` add one deterministic `explanation` object inside each alert, while preserving the same five top-level fields and adding no top-level `explanations` field.

## Local Report Review Demo

Create a clean temporary report directory and generate one authentication report with stored deterministic explanations:

```bash
rm -rf /tmp/sentinellite-v06-demo-reports
python -m sentinellite scan-auth examples/auth_logs/sample_auth.log --output-dir /tmp/sentinellite-v06-demo-reports --include-explanations
```

List the compatible reports in that explicit directory:

```bash
python -m sentinellite reports list --report-dir /tmp/sentinellite-v06-demo-reports
```

Use the Python standard library to print the exact generated report path:

```bash
python - <<'PY'
from pathlib import Path

reports = sorted(Path("/tmp/sentinellite-v06-demo-reports").glob("*.json"))
assert len(reports) == 1, reports
print(reports[0])
PY
```

Pass that exact path to `reports show`. For example:

```bash
REPORT_PATH="$(python - <<'PY'
from pathlib import Path

reports = sorted(Path("/tmp/sentinellite-v06-demo-reports").glob("*.json"))
assert len(reports) == 1, reports
print(reports[0])
PY
)"
python -m sentinellite reports show "$REPORT_PATH"
```

The review commands read only local report files and do not modify them. `reports show` prints a normalized summary and compact alert fields without evidence or raw JSON by default. It displays only whether a stored explanation object is present; it does not print the explanation body or regenerate an explanation from current templates.

## Local Notification Summary Export Demo

Generate one report from the bundled Ubuntu-style fixture and prepare a separate output directory:

```bash
rm -rf /tmp/sentinellite-v08-report /tmp/sentinellite-v08-notifications
mkdir -p /tmp/sentinellite-v08-notifications
python -m sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log --output-dir /tmp/sentinellite-v08-report
```

Resolve the exact generated report path:

```bash
REPORT_PATH="$(python - <<'PY'
from pathlib import Path

reports = sorted(Path("/tmp/sentinellite-v08-report").glob("*.json"))
assert len(reports) == 1, reports
print(reports[0])
PY
)"
```

Export the separate notification summary:

```bash
python -m sentinellite reports export-notification "$REPORT_PATH" --output /tmp/sentinellite-v08-notifications/alert-summary.json
```

Review the original alert report after export:

```bash
python -m sentinellite reports list --report-dir /tmp/sentinellite-v08-report
python -m sentinellite reports show "$REPORT_PATH"
```

Inspect the notification summary with the Python standard library:

```bash
python - <<'PY'
import json
from pathlib import Path

path = Path("/tmp/sentinellite-v08-notifications/alert-summary.json")
summary = json.loads(path.read_text(encoding="utf-8"))
expected_keys = {
    "schema_version",
    "output_type",
    "source",
    "alert_count",
    "included_alert_count",
    "omitted_alert_count",
    "severity_counts",
    "risk_level_counts",
    "alerts",
}
assert set(summary) == expected_keys
assert summary["output_type"] == "sentinellite_notification_summary"
print(json.dumps(summary, indent=2, sort_keys=True))
PY
```

The exporter reads only the explicitly selected existing report and uses its stored reviewed data. It does not collect events, run detection, rescore alerts, regenerate explanations, or send anything. The output is local JSON only, and the source report remains unchanged.

Keep notification summaries in a separate location such as `/tmp/sentinellite-v08-notifications` or `notifications/`. Do not place them in `reports/`: `reports list` treats lowercase `.json` files as alert-report candidates, while notification summaries intentionally use an independent schema.

## Safe Demo Notes

- SentinelLite AI is a defensive-only project.
- Its implemented collectors perform read-only observations.
- Authentication source inventory is read-only and never starts a scan automatically.
- Authentication scans require an explicitly selected path with existing authorized read access.
- SentinelLite AI does not invoke `sudo` or modify log permissions or ownership.
- It does not perform port scanning.
- It does not send network packets.
- It does not repair or modify observed files.
- Report listing and review are local and read-only.
- Report review does not print evidence or raw JSON by default.
- Stored explanations are not regenerated during report review.
- Notification export is local only, uses stored reviewed report data, and leaves the source report unchanged.
- Notification summaries are privacy-minimized but remain sensitive operational artifacts.
- Notification export performs no external delivery, network traffic, external API calls, real AI, or LLM execution.
- Alerts are investigation-focused and do not claim malware classification.
- Deterministic explanations are local rule templates and do not call an AI model, LLM, or API.
- AI-assisted alert explanation is planned but is not implemented yet.

Only demonstrate the project on systems and data that you are authorized to observe.

## Recommended Demo Flow

1. Show the README and introduce the defensive project scope.
2. Run the Ruff and Pytest quality checks.
3. Run the main CLI status command.
4. Create and inspect `sentinellite.toml` with `config-init`.
5. Run `auth-sources list` and explain inventory-only behavior.
6. Scan both bundled Linux authentication text fixtures with explicit paths.
7. Review a fixture report with `reports list` and `reports show`.
8. Export a privacy-minimized notification summary into a separate notification directory.
9. Run the authentication scan with explicit `--config` selection.
10. Demonstrate configured reporting, rule disabling, and module gating.
11. Run the process scan.
12. Run the network observation scan.
13. Run the file integrity observation scan.
14. Create and scan a file integrity baseline.
15. Review deterministic explanation panels when a scan produces alerts.
16. Compare default and opt-in JSON reports and show the nested per-alert explanation.
17. Explain the current limitations and next roadmap items.

## Current Limitations

- There is no persistent monitoring daemon yet.
- Report review has no filters, database, or persistent index.
- There is no dashboard yet.
- Config files must be selected explicitly with `--config`; automatic discovery is not implemented.
- Authentication log paths must be selected explicitly; there is no automatic source selection or config source setting.
- Journald and compressed rotated authentication logs are not supported in v0.7.
- Candidate file availability under `/var/log` is system-dependent.
- JSON explanation export requires `--include-explanations` or `reporting.include_explanations = true` in an explicitly selected config.
- Notification export is JSON only and has no notification configuration settings.
- The notification output parent directory must exist, and the output file must not already exist.
- Notification summaries should not be placed in `reports/` because they are not alert reports.
- Email, Slack, Discord, webhook, SMS, and other provider delivery integrations are not implemented.
- Notification export sends no network traffic and uses no tokens or external APIs.
- AI-assisted explanation is not implemented yet.
- The project has a Linux-first design; macOS is supported as a development mode.
