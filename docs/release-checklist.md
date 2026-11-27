# SentinelLite AI Release Checklist

Use this checklist for the exact commit proposed for a SentinelLite AI GitHub pre-release.
The checklist verifies the existing local defensive CLI; it does not authorize new product
capabilities or publication to PyPI.

## Published v1.3.0-beta Release Record

`v1.3.0-beta` was published as a
[GitHub pre-release](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.3.0-beta)
at `2026-11-27T07:45:25Z`. Release ID `460294277` has draft `false` and prerelease `true`.
Annotated tag `b13fe9c6030b2422ab45a7df8060f133fa452f8a` points to
`bf84cf93b40fa73f6489cc4312b2769bcb93204f`. The Python package version is `1.3.0b0`.

- Ubuntu x86-64 CI passed on Python 3.11 and 3.14. Final macOS 27.2.1 ARM64 validation
  passed 1,991 tests on Python 3.14.6, along with Ruff, `pip check`, and whitespace checks.
- The wheel and sdist built successfully. Before publication, all three uploaded assets
  were downloaded and checksum-verified. The downloaded wheel passed isolated installation
  and synthetic demo/dashboard smoke checks. Manual Safari inspection showed one report,
  three alerts, highest severity medium, and zero skipped files.
  [Verified release hashes](release-notes-v1.3.0-beta.md#release-assets-and-sha-256-hashes).
- On November 27, 2026, the owner deferred exact-wheel Ubuntu ARM64 validation because the
  VM was unavailable. The check remains unverified under an exception specific to
  `v1.3.0-beta`. Future release gates still apply.
  [Issue #17](https://github.com/kavisara-samarakoon/sentinellite-ai/issues/17).

## Completed v1.2.0-beta Release Record

`v1.2.0-beta` is published as a
[GitHub pre-release](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.2.0-beta)
at `2026-09-12T05:37:29Z` (draft: `false`, pre-release: `true`). The CLI display version is
`1.2.0-beta` and normalized Python package version is `1.2.0b0`.

- Git tag: `v1.2.0-beta`
- Annotated tag object: `548c4ce46de9dbbf52cf43fd9f5cb541224fa03f`
- Tag target commit: `d60813350cbb2b1e09ed99c6afa15442f280e043`
- Final validation passed: `pip check`, both version entry points, dashboard export help,
  Ruff, 652 automated tests, and `git diff --check`.
- Clean wheel smoke passed: installation and version output, 3 synthetic events and
  3 alerts from `demo`, and export to `reports/dashboard.html` with the dashboard title
  and `AUTH-001` / `AUTH-002` / `AUTH-003` rows.
- Published wheel, sdist, and `SHA256SUMS.txt` hashes are recorded in the
  [release notes](release-notes-v1.2.0-beta.md#release-assets-and-sha-256-hashes).

ARM-SecNet evidence remains scoped to one Ubuntu 26.04 LTS `aarch64` VM at SentinelLite
source commit `d1775f0ca09d714f5ed9d681af90f216c1c39e8e`. It does not establish a new VM run
at the published release commit or universal ARM64 compatibility.

The unchecked sections below apply to future releases. Set version expectations to the
intended release and record each gate against its exact source commit. Preserve the tags
and assets of published releases.

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
python -m ruff check --no-cache src tests
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider
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

- [ ] Console and module entry points both display the intended release version exactly.
- [ ] Installed package metadata reports the intended normalized version, derived from
      `sentinellite.__version__`.
- [ ] Both entry points expose the same command tree.
- [ ] Bare status works outside the repository checkout.
- [ ] Bare status uses an explicitly selected TOML config.
- [ ] `--version` exits without loading config or collecting system information.
- [ ] Help and status describe an on-demand local CLI, not a resident agent or service.

## 4. Build and Isolated Install

```bash
python -m build
```

- [ ] The final build produces the intended version's wheel and sdist in a clean output directory.
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
- [ ] New alert reports pass the canonical `parse_report_json()` validator and contain
      exactly `schema_version`, `report_id`, `report_type`, `generated_at`, `alert_count`,
      and `alerts`, as specified in [Data Contracts](data-contracts.md).
- [ ] Alert-report `schema_version` is integer `1`, never a boolean.
- [ ] Complete historical unversioned reports pass validation as `legacy-unversioned`
      without being rewritten or silently upgraded.
- [ ] Future report versions are rejected as unsupported; malformed and incompatible
      inputs fail without partial projections. Alerts and optional explanations validate fully.
- [ ] `reports list` distinguishes `valid (v1)`, `valid (legacy)`, `invalid`, and `unsupported`;
      `reports show` displays the correct contract/version and rejects invalid inputs.
- [ ] No default report has a top-level or per-alert explanation.
- [ ] An opt-in explained report keeps the same top-level keys and nests explanations per alert.
- [ ] Notification schema version remains `1` and its exact keys pass assertions.
- [ ] Notification output includes at most 20 alerts and records any omitted count.
- [ ] Privacy assertions exclude messages, evidence, explanation text, and sensitive fixture values.
- [ ] Notification export leaves the source report byte-for-byte unchanged.
- [ ] Alert reports and notification summaries remain in separate directories.

### Doctor, Synthetic Demo, and Dashboard Smoke

Use another fresh directory so dashboard counts are independent of other fixture reports:

```bash
dashboard_root="$(mktemp -d /tmp/sentinellite-dashboard-check.XXXXXX)"
sentinellite doctor --output-dir "$dashboard_root/reports"
sentinellite demo --output-dir "$dashboard_root/reports"
sentinellite dashboard export --help
sentinellite dashboard export --reports-dir "$dashboard_root/reports" \
  --output "$dashboard_root/dashboard.html" --limit 25
test -s "$dashboard_root/dashboard.html"
```

- [ ] Doctor checks local installation readiness; any platform warning is recorded.
- [ ] Demo uses only synthetic data and produces 3 synthetic events and 3 alerts.
- [ ] Dashboard shows 1 loaded report, 3 alerts, and highest severity medium.
- [ ] The saved HTML opens manually as a local file, with no server or browser auto-open.
- [ ] Dashboard export reads only existing local reports and leaves them unchanged.
- [ ] No external scripts/assets, network requests, live monitoring, or remediation occur.
- [ ] Dashboard accepts complete schema-v1 and legacy reports, counts invalid and unsupported
      candidates as skipped, and preserves source files, stored scores, and explanations.
- [ ] Regression tests cover empty input, invalid reports, and HTML escaping.

## 6. Platform Validation

### ARM-SecNet Evidence Cross-check

- [ ] Cross-check the separate [Lab 03 evidence record](https://github.com/kavisara-samarakoon/arm-secnet/blob/d3d9a7153939f58ebe9c08215ea4211c65472595/docs/evidence/v1.1-sentinellite-dashboard.md).
- [ ] Record its scope: one Ubuntu 26.04 LTS `aarch64` VM running SentinelLite source commit
      `d1775f0ca09d714f5ed9d681af90f216c1c39e8e`, before the `v1.2.0-beta` version bump.
- [ ] Confirm doctor: 10 passed, 0 warnings, 0 failed; demo: 3 synthetic events, 3 alerts;
      dashboard: local static HTML generated from local JSON reports.
- [ ] Confirm ARM-SecNet documentation/evidence validation after merge: 29 passed,
      0 warnings, 0 failures. These are documentation/evidence checks, not SentinelLite tests.
- [ ] State that this evidence does not prove universal ARM64 compatibility or validate the
      exact candidate commit. Both projects remain separate with no runtime dependency.

### Exact Candidate Checks

- [ ] Final macOS development validation passes on the exact candidate source state.
- [ ] Final Ubuntu ARM64 validation passes on the exact candidate source state.
- [ ] Each record includes OS, architecture, Python/tool versions, commit SHA, command results,
      test count, schema/privacy results, and final worktree status.
- [ ] Ubuntu authentication validation uses bundled fixtures only. Candidate inventory does
      not become a real `/var/log/auth.log` or `/var/log/secure` scan.
- [ ] Environment-dependent process and network checks are identified as authorized,
      on-demand observations and not deterministic security outcomes.

## 7. PR, Tag, and GitHub Pre-release

- [ ] The GitHub pull request shows passing full-suite CI for the final reviewed commit
      on both configured Python versions, including canonical report contract assertions.
- [ ] Review confirms no out-of-scope capability or safety-boundary change.
- [ ] Final release notes match the validated behavior and known limitations.
- [ ] The annotated release tag points to the exact reviewed release commit.
- [ ] The GitHub release is marked as a pre-release.
- [ ] The release is not published to PyPI as part of this checklist.
- [ ] Uploaded artifacts were built from the tagged commit.
- [ ] After the final build, collect wheel/sdist SHA-256 hashes and the `SHA256SUMS.txt`
      asset digest; these remain pending during candidate preparation.
- [ ] Verify attached artifacts against those final hashes and publish their checksums.
- [ ] Replace pending release status only after the release exists, recording its actual
      publication timestamp and reviewed tag commit.
- [ ] A fresh environment can install the uploaded wheel and pass the isolated smoke checks.
- [ ] No tag or release is created until every mandatory gate above is complete.
