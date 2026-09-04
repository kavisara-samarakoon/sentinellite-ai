# SentinelLite AI Release Checklist

Use this checklist for the exact commit proposed for a SentinelLite AI GitHub pre-release.
The checklist verifies the existing local defensive CLI; it does not authorize new product
capabilities or publication to PyPI.

## 1. Scope and Source State

- [ ] The release branch is focused and based on the intended `main` commit.
- [ ] `git status --short` is empty before validation.
- [ ] The diff contains no generated reports, notification summaries, baselines, caches,
      environments, build directories, credentials, real logs, or host-specific evidence.
- [ ] No collector, detection, scoring, alert-report, or notification-summary behavior
      changed without an explicitly approved bug fix and focused regression test.
- [ ] Current-facing text makes no production EDR, real AI/LLM, external delivery, daemon,
      background monitoring, active scanning, exploitation, or remediation claim.

## 2. Installation and Quality Checks

Use a clean clone or disposable validation copy:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip check
ruff check --no-cache src tests
PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider
git diff --check
```

- [ ] Editable installation succeeds without `PYTHONPATH`.
- [ ] `pip check` reports no broken requirements.
- [ ] Ruff passes.
- [ ] The complete Pytest suite passes.
- [ ] `git diff --check` passes.
- [ ] The checkout remains clean after validation.

## 3. Version and Entry Points

```bash
sentinellite --version
python -m sentinellite --version
sentinellite --help
python -m sentinellite --help
sentinellite
python -m sentinellite
```

- [ ] Console and module entry points display the intended release version exactly.
- [ ] Both entry points expose the same command tree.
- [ ] Bare status works outside the repository checkout.
- [ ] Bare status uses an explicitly selected TOML config.
- [ ] `--version` exits without loading config or collecting system information.
- [ ] Help and status describe an on-demand local CLI, not a resident agent or service.

## 4. Build and Isolated Install

```bash
python -m build --wheel
```

- [ ] Exactly one expected wheel is produced.
- [ ] Wheel metadata contains the normalized intended version.
- [ ] The wheel contains Python package modules and `sentinellite/config/default.yaml`.
- [ ] The wheel contains the MIT License metadata and license file.
- [ ] The console entry point is `sentinellite = sentinellite.main:cli`.
- [ ] The wheel installs successfully into a fresh virtual environment.
- [ ] `pip check`, both version commands, help, and bare status pass from outside the checkout.
- [ ] If additional artifacts are uploaded, each artifact is built and inspected from the
      exact release commit rather than reused from an earlier run.

## 5. Fixture, Report, and Notification Smoke

Use fresh, separate temporary directories and bundled fixtures only:

```bash
validation_root="$(mktemp -d /tmp/sentinellite-release.XXXXXX)"
report_dir="$validation_root/reports"
notification_dir="$validation_root/notifications"
mkdir -p "$notification_dir"

sentinellite auth-sources list
sentinellite scan-auth examples/auth_logs/sample_ubuntu_auth.log \
  --output-dir "$report_dir"
sentinellite reports list --report-dir "$report_dir"

report_path="$(find "$report_dir" -maxdepth 1 -type f -name '*.json' -print)"
sentinellite reports show "$report_path"
sentinellite reports export-notification "$report_path" \
  --output "$notification_dir/alert-summary.json"
```

- [ ] No real host authentication log is read or scanned.
- [ ] Fixture event and alert counts match the tested expectation.
- [ ] `reports list` and `reports show` accept the generated alert report.
- [ ] Default alert-report top-level keys match [Data Contracts](data-contracts.md) exactly.
- [ ] No default report has a top-level or per-alert explanation.
- [ ] An opt-in explained report keeps the same top-level keys and nests explanations per alert.
- [ ] Notification schema version remains `1` and its exact keys pass assertions.
- [ ] Notification output includes at most 20 alerts and records any omitted count.
- [ ] Privacy assertions exclude messages, evidence, explanation text, and sensitive fixture values.
- [ ] Notification export leaves the source report byte-for-byte unchanged.
- [ ] Alert reports and notification summaries remain in separate directories.

## 6. Platform Validation

- [ ] Final macOS development validation passes on the exact candidate source state.
- [ ] Final Ubuntu ARM64 validation passes on the exact candidate source state.
- [ ] Each record includes OS, architecture, Python/tool versions, commit SHA, command results,
      test count, schema/privacy results, and final worktree status.
- [ ] Ubuntu authentication validation uses bundled fixtures only. Candidate inventory does
      not become a real `/var/log/auth.log` or `/var/log/secure` scan.
- [ ] Environment-dependent process and network checks are identified as authorized,
      on-demand observations and not deterministic security outcomes.

## 7. PR, Tag, and GitHub Pre-release

- [ ] The GitHub pull request shows passing CI for the final reviewed commit.
- [ ] Review confirms no out-of-scope capability or safety-boundary change.
- [ ] Final release notes match the validated behavior and known limitations.
- [ ] The annotated release tag points to the exact reviewed release commit.
- [ ] The GitHub release is marked as a pre-release.
- [ ] The release is not published to PyPI as part of this checklist.
- [ ] Uploaded artifacts were built from the tagged commit.
- [ ] SHA-256 checksums are published for every attached artifact.
- [ ] A fresh environment can install the uploaded wheel and pass the isolated smoke checks.
- [ ] No tag or release is created until every mandatory gate above is complete.
