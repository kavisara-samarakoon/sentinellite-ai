# Contributing to SentinelLite AI

SentinelLite AI welcomes focused contributions that preserve its defensive, local, and investigation-oriented scope.

The supported development baseline is Python 3.11 or newer. SentinelLite AI is an
on-demand CLI; contributions must not imply or introduce resident, background, or
production EDR behavior.

## Setup

From a cloned repository, create an isolated environment and install the development tools:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Validation

Run the checks relevant to the change, and run the full set before opening a pull request:

```bash
python -m pip check
ruff check --no-cache src tests
PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider
python -m build --wheel
sentinellite --version
python -m sentinellite --version
```

Remove generated `dist/`, `build/`, and `src/sentinellite_ai.egg-info/` directories after local wheel validation. Do not commit build products, generated reports or notification summaries, caches, secrets, or real host logs.

Release preparation must also follow the [release checklist](docs/release-checklist.md),
including clean-checkout package, fixture, schema, privacy, and platform validation.

## Branches and Commits

- Use a focused feature or fix branch.
- Keep commits small enough to review and describe their intent clearly.
- Add focused tests for behavior changes and preserve backward-compatible CLI and data contracts.
- Submit a pull request only after reviewing the diff and running the applicable validation.

## Safety Boundaries

- Keep features defensive and limited to authorized endpoint observation and local review.
- Do not add offensive tooling, exploitation, port scanning, packet sending, external notification delivery, or secret/provider integrations.
- Do not add real AI or LLM execution, automatic remediation, process termination, IP blocking, firewall changes, or file deletion and repair.
- Do not add a daemon, scheduler, background watcher, application network traffic, or automatic source discovery.
- Do not describe SentinelLite AI as a production EDR or claim that investigation signals prove compromise or malware.
