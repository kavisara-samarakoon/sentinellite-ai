# ARM-SecNet Integration Guide

ARM-SecNet provides an Apple Silicon / UTM / Ubuntu ARM64 lab environment.
SentinelLite AI can be installed inside that VM as an optional, local, on-demand,
defensive endpoint observation and report-review CLI.

## Scope and Repository Relationship

This is documentation-based integration only. ARM-SecNet and SentinelLite AI remain
separate repositories. Do not merge their repositories or introduce a runtime dependency
between them. ARM-SecNet provides the VM environment; SentinelLite AI is installed and
invoked independently inside the VM.

This guide covers the `v1.1.0-beta` release candidate, which includes `doctor` and `demo`.
The candidate is not yet published as a GitHub release. Before release, install from
`feature/v1.1-product-usability`; after release, use the `v1.1.0-beta` wheel. The current
stable `v1.0.0-beta` wheel does not include these commands.

These instructions describe a lab workflow. They do not establish completed ARM-SecNet
runtime validation or comprehensive Ubuntu ARM64 compatibility.

## Required Environment

- An Apple Silicon Mac
- UTM
- An Ubuntu ARM64 VM provided by the ARM-SecNet lab setup
- Python 3.11 or newer inside the VM, with virtual-environment support
- Git for the source installation
- A local, authorized lab environment and a writable working directory inside the VM

Run the following commands in the Ubuntu VM terminal with a normal user account.
SentinelLite commands do not require root for the installation checks and synthetic demo.
Source downloads and dependency installation need network access; the local CLI workflow
below does not send network traffic.

## Verify the VM

```bash
uname -m
python3 --version
```

The expected architecture is `aarch64`. Confirm that the Python version is 3.11 or newer
before creating the virtual environment. If either check differs, correct the VM or
Python setup before continuing. Architecture output identifies the guest architecture;
it does not by itself validate SentinelLite's observation capabilities.

## Install from Source for Development

Before the `v1.1.0-beta` release, install the candidate from this branch:

```bash
git clone https://github.com/kavisara-samarakoon/sentinellite-ai.git
cd sentinellite-ai
git switch feature/v1.1-product-usability
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
sentinellite --version
```

Keep this checkout separate from ARM-SecNet. The editable installation uses this
SentinelLite checkout; it does not install or import ARM-SecNet as a dependency. Keep the
virtual environment active for subsequent commands. The expected version output is
`SentinelLite AI v1.1.0-beta`.

## Install from a GitHub Release Wheel

SentinelLite AI is not published to PyPI yet. **After the `v1.1.0-beta` GitHub release is
published**, download its wheel and `SHA256SUMS.txt` from that release's assets. No
`v1.1.0-beta` release or download availability is claimed here. Until release, use the
source installation above.

After release, make the downloaded files available inside the Ubuntu VM and verify the
wheel against `SHA256SUMS.txt`. In the directory containing the verified wheel, create a
separate environment:

```bash
python3 -m venv .venv-release
source .venv-release/bin/activate
python -m pip install --upgrade pip
python -m pip install ./sentinellite_ai-1.1.0b0-py3-none-any.whl
sentinellite --version
```

The `v1.1.0-beta` wheel should print `SentinelLite AI v1.1.0-beta` and includes `doctor` and
`demo`. The already published `v1.0.0-beta` wheel described in the
[README installation instructions](../../README.md#install-from-github-release) does not
include them. Keep the environment for your `v1.1.0-beta` installation active below.

## First Safe Commands

With the `v1.1.0-beta` environment active (source before release, or wheel after release), run:

```bash
sentinellite doctor
sentinellite demo
```

`doctor` checks local installation readiness only: SentinelLite and Python versions,
system and architecture, packaged default configuration, dependency imports, and report
directory write access. It can create the report directory, writes a temporary probe,
and removes that probe. It does not scan logs or assess endpoint security. Review its
PASS/WARNING/FAIL summary; failures exit with code 1, while passes and warnings exit with
code 0. Typer and Rich must be installed for the CLI to start.

`demo` uses bundled synthetic fixture data only. It does not read real logs, observe
processes, network connections or files, or send network traffic. It applies the existing
authentication processing and report pipeline to synthetic events, saves a normal JSON
report with the existing schema, and prints its path and suggested review commands.
Synthetic alerts are examples for learning the report-review workflow, not findings
about the VM.

## Review the Report

```bash
sentinellite reports list
sentinellite reports show <REPORT_PATH>
```

Replace `<REPORT_PATH>` with the actual saved report path printed by `demo`; quote the
path if it contains spaces. By default, reports are saved under `reports` in the current
working directory. Run the review commands from that same directory. If you selected a
different output directory, follow the exact commands printed by `demo`.

Report review reads saved local reports. It does not start a new observation, send a
notification, or modify the source report. See the [demo guide](../demo-guide.md) for a
longer fixture workflow.

## Optional Authorized Local Observations

The following commands are optional and authorized-only. Run them only inside the lab VM
on systems and data you are permitted to observe, after completing the synthetic demo:

```bash
sentinellite auth-sources list
sentinellite scan-process
sentinellite scan-network
sentinellite scan-files README.md
```

- `auth-sources list` inventories known local authentication-log candidates without
  reading their contents or starting an authentication scan.
- `scan-process` observes process metadata available to the current user.
- `scan-network` reads active connection metadata exposed by the OS. It does not scan
  ports, probe hosts, send packets, open connections, or perform DNS lookups.
- `scan-files README.md` observes the explicitly selected file. Run it from the SentinelLite
  source checkout so `README.md` exists; it does not recurse through directories.

The scan commands run once and write local reports. Available metadata and results vary
with the VM state and the current user's permissions. Do not elevate privileges just to
complete this walkthrough. Empty results are not proof that the endpoint is secure.

## Screenshot and Evidence Checklist

Capture the following from the Ubuntu VM using `v1.1.0-beta` installed from source before
release, or from its wheel after release:

- [ ] `uname -m` output showing `aarch64`
- [ ] `python3 --version` output showing Python 3.11 or newer
- [ ] `sentinellite --version` output
- [ ] `sentinellite doctor` output, including the summary and any failures or warnings
- [ ] `sentinellite demo` output, including the saved report path
- [ ] `sentinellite reports list` and `sentinellite reports show <REPORT_PATH>` output

Record the Ubuntu release and SentinelLite branch/commit alongside the evidence so the
results can be tied to a specific lab run. Label demo reports as synthetic. Review and
redact sensitive host, user, path or network details before sharing screenshots or reports,
especially if you ran the optional observations. Keep real host reports out of both repos.

## Safety Boundaries

This integration does not provide production monitoring, production EDR, antivirus,
a SIEM, a SOC platform, a malware remover, or an enterprise security platform.

- There is no daemon, background monitoring, or scheduled observation.
- There is no exploitation, active network scanning, packet sending, or firewall change.
- There is no remediation, process killing, or automatic response action.
- There is no external notification delivery; report review stays local.
- SentinelLite AI is not real AI/LLM-powered. Explanations use deterministic local
  templates, and no AI model or external LLM service runs.
- Alerts support authorized defensive investigation and do not prove malware or compromise.

See the [security policy](../../SECURITY.md) for the project's full boundaries.

## Possible Future Work

Future work may include deeper ARM-SecNet validation notes, a later evaluation of TestPyPI
distribution, and optional AI architecture planning. These are possible future directions,
not capabilities delivered by this integration. This guide adds no TestPyPI or PyPI
publishing and no real AI/LLM integration.
