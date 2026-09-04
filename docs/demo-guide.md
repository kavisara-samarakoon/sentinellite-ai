# SentinelLite AI Demo Guide

## Purpose

This is the deterministic golden path for demonstrating the SentinelLite AI
`v1.0.0-beta` release surface. It uses bundled, non-sensitive authentication fixtures and isolated
temporary output. It does not require elevated privileges, read real authentication-log
contents, or rely on environment-dependent alert results.

SentinelLite AI is an on-demand local defensive CLI, not a daemon, background monitor,
production EDR, external notification service, or AI/LLM system.

## Prerequisites

- A trusted clone of the repository
- Python 3.11 or newer
- Git
- A shell with `mktemp`

Run all commands from the repository root. The installed `sentinellite` command is used
below. `python -m sentinellite` is an equivalent supported entry style while the virtual
environment is active.

## 1. Create an Isolated Environment

Create the virtual environment and all generated demo output outside the repository:

```bash
demo_root="$(mktemp -d /tmp/sentinellite-demo.XXXXXX)"
python3 -m venv "$demo_root/venv"
source "$demo_root/venv/bin/activate"
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip check

report_dir="$demo_root/reports"
notification_dir="$demo_root/notifications"
mkdir -p "$notification_dir"
```

The fresh temporary directory prevents earlier reports from affecting file discovery. No
cleanup command is required during the demonstration. The temporary directory can be
reviewed and removed later using the normal controls of the host environment.

## 2. Verify the Installed CLI

```bash
sentinellite --version
python -m sentinellite --version
sentinellite --help
```

Both version commands must print the same version. The help output should describe a local
defensive observation and report-review CLI, not a resident agent or service.

For the current release candidate, both commands print `SentinelLite AI v1.0.0-beta`.

## 3. Show Local Status

```bash
sentinellite
```

The status screen describes capabilities available to explicit commands. It does not start
collection, scheduling, or a background process. It also identifies real AI/LLM execution
as not implemented; alert explanations are deterministic local templates.

Create the example TOML outside the repository and display status with it explicitly:

```bash
sentinellite config-init --path "$demo_root/sentinellite.toml"
sentinellite --config "$demo_root/sentinellite.toml"
```

SentinelLite AI does not discover this file automatically. The selected config affects the
displayed module state and the commands run with that same `--config` option.

## 4. Inventory Authentication Source Candidates

```bash
sentinellite auth-sources list
```

This command performs local, read-only inventory of the two known candidate paths. It does
not read or print `/var/log` file contents, choose a source, invoke `sudo`, change
permissions, or start `scan-auth`. Do not substitute a live host log in this demo.

## 5. Scan a Bundled Fixture

Run the Ubuntu/Debian-style fixture with an explicit temporary report directory:

```bash
sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log \
  --output-dir "$report_dir"
```

The fixture covers the currently recognized traditional failed SSH password, accepted SSH
password, and sudo record shapes. It is test data, not proof of comprehensive Ubuntu or
Debian compatibility. The command produces deterministic fixture event and alert counts,
then writes one local alert report.

The RHEL/Fedora-style fixture can be demonstrated separately in a new output directory:

```bash
rhel_report_dir="$demo_root/rhel-reports"
sentinellite scan-auth examples/auth_logs/sample_rhel_secure.log \
  --output-dir "$rhel_report_dir"
```

This is fixture-format validation only; it is not RHEL or Fedora runtime validation.

## 6. List and Review the Report

```bash
sentinellite reports list --report-dir "$report_dir"
```

Resolve the exact fixture report path and review its safe terminal summary:

```bash
report_path="$(find "$report_dir" -maxdepth 1 -type f -name '*.json' -print)"
test -n "$report_path"
sentinellite reports show "$report_path"
```

Because `report_dir` was fresh and the fixture scan writes one report, this resolves one
path. `reports show` does not print alert evidence or raw JSON by default and does not
regenerate stored explanations.

## 7. Export a Local Notification Summary

```bash
notification_path="$notification_dir/alert-summary.json"
sentinellite reports export-notification "$report_path" \
  --output "$notification_path"
```

The exporter reads stored reviewed report data and writes a separate privacy-minimized JSON
contract. It does not modify the source report, collect new events, rerun detection, rescore
alerts, regenerate explanations, make network requests, or send anything externally.

Keep alert reports and notification summaries in separate directories:

```text
$demo_root/reports/          SentinelLite alert reports
$demo_root/notifications/    local notification summaries
```

Notification summaries are not alert reports. They remain sensitive operational artifacts
even though messages, evidence, explanation bodies, usernames, addresses, paths, process
details, and hashes are excluded.

## 8. Optional Contract Check

Use the Python standard library to check the two distinct top-level contracts:

```bash
python - "$report_path" "$notification_path" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
notification = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

assert set(report) == {
    "report_id",
    "report_type",
    "generated_at",
    "alert_count",
    "alerts",
}
assert "explanations" not in report
assert notification["schema_version"] == 1
assert notification["output_type"] == "sentinellite_notification_summary"
assert notification["included_alert_count"] <= 20
print("Alert-report and notification-summary contracts verified.")
PY
```

See [Data Contracts](data-contracts.md) for the complete compatibility description.

## Optional Environment-Dependent Commands

These commands are outside the deterministic golden path because they observe the current
authorized host and their results vary:

```bash
sentinellite scan-process --output-dir "$demo_root/process-reports"
sentinellite scan-network --output-dir "$demo_root/network-reports"
sentinellite scan-files README.md --output-dir "$demo_root/file-reports"
```

Use them only in an authorized development or disposable validation environment. The
network command reads connection metadata; it does not scan ports, probe hosts, send
packets, open connections, or perform DNS lookups. These commands run once and exit.

## Demo Safety Summary

- Use bundled authentication fixtures only.
- Do not run the demo with `sudo` or change log permissions.
- Do not pass a real host authentication log to `scan-auth`.
- Do not place notification summaries inside the alert-report directory.
- Do not describe alerts as proof of malware or compromise.
- Do not describe deterministic explanations as AI-generated.
- Do not imply daemon, background, external-delivery, or remediation behavior.
- Do not commit reports, notifications, baselines, environments, caches, or real logs.

The project is intended for authorized defensive learning, demonstration, and local review.
