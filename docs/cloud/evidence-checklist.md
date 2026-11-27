# SentinelLite AI — Cloud VM Evidence Checklist

Use this checklist when recording results from an authorized Ubuntu VM validation run of
`v1.3.0-beta` (`1.3.0b0`). Keep raw reports, notifications, baselines, and sensitive host
metadata out of Git.

## 1. Preflight & Provenance

- [ ] Confirmed Bash, non-root user (`id -u != 0`), `umask 077`, Ubuntu Linux, expected `EXPECTED_ARCH`
      (`x86_64` or `aarch64`), Python `>=3.11`, and `venv`/`ensurepip` without auto-installing OS packages.
- [ ] Recorded `uname -a`, `uname -m`, `/etc/os-release`, and `python3 --version`.
- [ ] Verified `FIXTURE_REPO_DIR` commit is `bf84cf93b40fa73f6489cc4312b2769bcb93204f`, clean
      working tree, and unmodified fixture files.
- [ ] Enforced fail-closed SHA-256 verification (without `--ignore-missing`) for `SHA256SUMS.txt`
      (`9c18c75a257c7c7d0668200c0a23b419f781041055bef64c8a93f9f25ec24fc4`) and
      `sentinellite_ai-1.3.0b0-py3-none-any.whl`
      (`02fb7409a3e071d561700b9783af2136307669aaa332260d4324e20ea3c0dab3`).
- [ ] Installed wheel outside source checkout with `PYTHONPATH`/`PYTHONHOME`/`PYTHONOPTIMIZE` unset; recorded
      `pip check` and `pip list --format=freeze` (noting pure-Python wheel vs unlocked transitive dependencies).
- [ ] Confirmed `sentinellite --version` and `python -m sentinellite --version` both print
      `SentinelLite AI v1.3.0-beta`.

## 2. Core Readiness & Synthetic Workloads

- [ ] `sentinellite doctor` passed with `0` failures on Linux (no non-Linux platform warning).
- [ ] `sentinellite demo` produced exactly `1` schema-v1 report with `3` alerts (`AUTH-001`,
      `AUTH-002`, `AUTH-003`) in `DEMO_DIR`.
- [ ] `sentinellite dashboard export` generated `dashboard.html` with `Total reports loaded` = `1`,
      `Total alerts shown` = `3`, `Highest severity shown` = `medium`, `Skipped files: 0.`,
      `AUTH-001`–`AUTH-003`, restrictive CSP, and no `<script` tag.
- [ ] Distinguished headless HTML generation/content checks from interactive browser rendering.

## 3. Fixture, Schema, & Privacy Checks

- [ ] `auth-sources list` ran as inventory only (no `/var/log/*` scan).
- [ ] `scan-auth` on `$FIXTURE_REPO_DIR/examples/auth_logs/sample_ubuntu_auth.log` produced
      exactly `1` schema-v1 report with `3` alerts (`AUTH-001`, `AUTH-002`, `AUTH-003`).
- [ ] `reports list` and `reports show` passed on the generated report.
- [ ] `parse_report_json()` validated both the generated `schema-v1` report and
      `$FIXTURE_REPO_DIR/tests/fixtures/report_schema/legacy_unversioned_alert.json`
      (`LEGACY_UNVERSIONED`, `schema_version is None`, source bytes unchanged).
- [ ] `reports export-notification` preserved the source report SHA-256 and matched exact
      top-level and per-alert allowlists (`3` included, `0` omitted, integer `schema_version == 1`).

## 4. Disposable File Integrity & Optional Host Observations

- [ ] `scan-files`, unchanged `scan-files-baseline` (`0` alerts), and modified
      `scan-files-baseline` (`FIM-004` alert) ran in separate output directories, all three
      reports passed `schema-v1` validation, and the baseline JSON and monitored file were unchanged.
- [ ] Any opt-in `scan-process` / `scan-network` run was separately authorized, with partial
      non-root `/proc` visibility and sensitivity noted.
- [ ] Retained `WORK_ROOT` inspected locally, redacted evidence recorded, and workspace
      removed manually only after evidence acceptance.
