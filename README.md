# SentinelLite AI

SentinelLite AI is an on-demand, local, defensive Linux endpoint observation and
report-review CLI. It collects selected host facts when a command is run, applies
transparent rules, assigns deterministic risk scores, writes local JSON alert reports,
and presents rule-based investigation guidance.

It is not a production EDR. It does not run as a daemon or background service, send
notifications externally, make application network requests, execute a real AI or LLM,
or perform automatic remediation.

## Status

The current version is `v1.0.0-beta`. It is in development and is not yet published as a
GitHub release. The previous published milestone is `v0.9.0-alpha`. This beta is a
release-surface stabilization milestone rather than a feature release and targets a stable
local defensive CLI for authorized development, demonstration, and evaluation.

The automated suite covers configuration, collectors,
normalization, detection, scoring, reporting, deterministic explanations, local report
review, notification-summary export, packaging, and CLI behavior.

## Safety Boundaries

SentinelLite AI is defensive and local:

- Every scan is started explicitly by the user; there is no daemon, scheduler, or watcher.
- Authentication scanning requires an exact user-selected file path.
- File integrity commands observe only explicit paths and do not recurse through directories.
- Network collection reads active connection metadata exposed by the operating system. It
  does not probe hosts, scan ports, send packets, open connections, or perform DNS lookups.
- Reports and notification summaries are written locally.
- Notification export does not send email, Slack, Discord, webhook, SMS, or provider traffic.
- Explanations are deterministic local templates. No AI model, LLM, or external explanation
  service is called.
- The project does not exploit systems, terminate processes, block IP addresses, modify
  firewalls, repair or delete files, or perform any automatic response action.
- Alerts are investigation aids. They do not prove malware, compromise, or unauthorized activity.

Use the project only on systems and data you are authorized to observe. Generated reports
can contain host, user, process, network, and file metadata and must be handled as sensitive.

See the [security policy](SECURITY.md) for the full scope.

## Requirements

- Python 3.11 or newer
- Git
- A Python virtual environment
- Linux for the target observation environment; macOS is supported for development checks

The package is not published to PyPI. Install it from a trusted clone or a separately
verified local release artifact.

## Installation

Clone the repository and create an isolated development environment:

```bash
git clone https://github.com/kavisara-samarakoon/sentinellite-ai.git
cd sentinellite-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip check
```

For a local installation without the development tools, use:

```bash
python -m pip install -e .
```

The installed `sentinellite` command is the primary entry point. The module entry point
remains supported and exposes the same command tree:

```bash
sentinellite --version
python -m sentinellite --version
sentinellite --help
python -m sentinellite --help
```

No `PYTHONPATH` setting is required after installation.

## Quick Start

Show the local CLI status:

```bash
sentinellite
```

Inventory common Linux authentication-log candidates without reading their contents or
starting a scan:

```bash
sentinellite auth-sources list
```

Run a deterministic demonstration against a bundled, non-sensitive fixture:

```bash
sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log
```

See the [demo guide](docs/demo-guide.md) for the complete fixture-to-report workflow.

## Explicit TOML Configuration

Create a default TOML file at an explicit path:

```bash
sentinellite config-init --path /tmp/sentinellite.toml
```

Select it with the global option:

```bash
sentinellite --config /tmp/sentinellite.toml scan-auth \
  examples/auth_logs/sample_ubuntu_auth.log
```

SentinelLite AI never discovers a config file automatically. Without `--config`, built-in
defaults are used. The generated config has this structure:

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

Relative `reporting.output_dir` paths are resolved from the selected config file's
directory. Reporting option precedence is:

```text
explicit CLI option > selected TOML config > built-in default
```

Module switches gate their corresponding commands before collection or output. Rule IDs
are validated, case-sensitive, and disabled before detection. Unknown config keys or rule
IDs fail cleanly. Automatic configuration discovery is not implemented.

## Commands

The current command surface is:

```text
sentinellite
sentinellite config-init [--path PATH]
sentinellite auth-sources list
sentinellite scan-auth LOG_PATH
sentinellite scan-process
sentinellite scan-network
sentinellite scan-files PATH...
sentinellite baseline-files PATH... --baseline-path PATH
sentinellite scan-files-baseline --baseline-path PATH
sentinellite reports list [--report-dir PATH]
sentinellite reports show REPORT_PATH
sentinellite reports export-notification REPORT_PATH --output OUTPUT_PATH
```

Alert-producing scan commands accept `--output-dir` and
`--include-explanations/--no-include-explanations`. Run `sentinellite COMMAND --help` for
the exact options.

### Authentication fixtures

The repository includes traditional text fixtures for the currently recognized failed
SSH password, accepted SSH password, and sudo record shapes:

```bash
sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log
sentinellite scan-auth examples/auth_logs/sample_rhel_secure.log
```

These fixtures do not establish comprehensive Ubuntu, Debian, RHEL, or Fedora support.
Journald and compressed rotated logs are not supported. A zero-event or zero-alert result
is not a general security guarantee.

`auth-sources list` inventories `/var/log/auth.log` and `/var/log/secure` as candidates
only. It does not read their contents, choose one automatically, or invoke `scan-auth`.
Real host-log scanning is not part of the documented demo or release validation.

### Optional environment-dependent observations

The following commands inspect the current authorized host and therefore produce
environment-dependent results:

```bash
sentinellite scan-process
sentinellite scan-network
sentinellite scan-files README.md
```

The process and network commands take one on-demand snapshot. File integrity collection
reads metadata and SHA-256 content hashes for explicitly selected regular files. None of
these commands performs remediation.

### Baseline file integrity

Create a trusted baseline for explicit paths, then compare those same paths later:

```bash
sentinellite baseline-files README.md pyproject.toml \
  --baseline-path /tmp/sentinellite-baseline.json
sentinellite scan-files-baseline \
  --baseline-path /tmp/sentinellite-baseline.json
```

The baseline command writes only the requested baseline JSON. The scan writes only its
alert report and never repairs or changes the observed files.

## Reports and Notification Summaries

Alert reports go to `reports/` by default. Generated notification summaries should go to
`notifications/` or another separate directory because they use a different contract.

```bash
sentinellite reports list
sentinellite reports show REPORT_PATH
mkdir -p notifications
sentinellite reports export-notification REPORT_PATH \
  --output notifications/alert-summary.json
```

Notification export uses stored report data, refuses to overwrite an existing output,
does not modify the source report, and performs no delivery. Although privacy-minimized,
the resulting summary still contains operational security metadata and remains sensitive.

The exact contracts and compatibility expectations are documented in
[Data Contracts](docs/data-contracts.md).

## Deterministic Explanations

When a scan produces scored alerts, the CLI renders local explanation panels generated
from rule-specific templates and evidence already present in each alert. Optional JSON
export nests one explanation object inside each alert:

```bash
sentinellite scan-auth examples/auth_logs/sample_auth.log \
  --include-explanations
```

This feature is deterministic rule-based guidance, not AI or LLM execution. It does not
invent evidence, classify malware, claim compromise, or take response actions.

## Development Validation

```bash
python -m pip check
ruff check --no-cache src tests
PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider
git diff --check
```

Release preparation must follow the [release checklist](docs/release-checklist.md).
Ubuntu ARM64 results and their limitations are recorded in the
[Linux validation notes](docs/linux-validation.md).

## Current Limitations

- Beta-quality local CLI; no production EDR or enterprise support claim
- On-demand execution only; no daemon, service, scheduler, or background watcher
- Traditional text authentication fixtures only in the documented validation flow
- No automatic auth-source or config discovery
- No journald or compressed rotated-log input
- No recursive file integrity scan
- No dashboard, database, persistent report index, or filters
- No external notification delivery or provider configuration
- No real AI or LLM execution
- No automatic remediation
- No ARM-SecNet integration in the v1 beta scope
- No PyPI publication

## Release History

Historical milestone notes remain available for reference:

- [v0.1.0-alpha](docs/release-notes-v0.1.0-alpha.md)
- [v0.2.0-alpha](docs/release-notes-v0.2.0-alpha.md)
- [v0.3.0-alpha](docs/release-notes-v0.3.0-alpha.md)
- [v0.4.0-alpha](docs/release-notes-v0.4.0-alpha.md)
- [v0.5.0-alpha](docs/release-notes-v0.5.0-alpha.md)
- [v0.6.0-alpha](docs/release-notes-v0.6.0-alpha.md)
- [v0.7.0-alpha](docs/release-notes-v0.7.0-alpha.md)
- [v0.8.0-alpha](docs/release-notes-v0.8.0-alpha.md)
- [v0.9.0-alpha](docs/release-notes-v0.9.0-alpha.md)

The in-development beta notes are available at
[v1.0.0-beta](docs/release-notes-v1.0.0-beta.md).

## License

SentinelLite AI is available under the [MIT License](LICENSE).

## Author

Kavisara Samarakoon
