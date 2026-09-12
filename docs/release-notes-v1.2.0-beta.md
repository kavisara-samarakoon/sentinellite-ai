# SentinelLite AI v1.2.0-beta — Local Dashboard and ARM-SecNet Lab Validation

## Published Release

`v1.2.0-beta` is published as a GitHub pre-release named **SentinelLite AI v1.2.0-beta**.

- [GitHub release](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.2.0-beta)
- Published at: `2026-09-12T05:37:29Z`
- Draft: `false`; pre-release: `true`
- Git tag: `v1.2.0-beta`
- Annotated tag object: `548c4ce46de9dbbf52cf43fd9f5cb541224fa03f`
- Tag target commit: `d60813350cbb2b1e09ed99c6afa15442f280e043`

The CLI display version is `1.2.0-beta`; normalized Python package metadata is `1.2.0b0`.
SentinelLite AI is not published to PyPI.

## Release Assets and SHA-256 Hashes

The GitHub release contains these final assets:

| Asset | SHA-256 |
| --- | --- |
| `sentinellite_ai-1.2.0b0-py3-none-any.whl` | `fc8c647921d1d2575cb0ac25e1a7f32191e8ea8e0363a90a4728bf59dae4ba15` |
| `sentinellite_ai-1.2.0b0.tar.gz` | `c3fa1c8e56e179b836f7533d84b5ee2383f75eb15b1f39a6892eb57da7f77ee5` |
| `SHA256SUMS.txt` | `276b978ba01b5e7b6d8232c778f647cd499e70f3e23d48d15dd9de0e7fd51afd` |

The `SHA256SUMS.txt` row is the digest of the checksum file itself.

## Final Release Validation

Before release, `pip check`, both version entry points, `dashboard export --help`, Ruff,
all **652 automated tests**, and `git diff --check` passed. Both entry points displayed
`SentinelLite AI v1.2.0-beta`.

The clean wheel smoke test passed: the wheel installed successfully, the version command
showed `SentinelLite AI v1.2.0-beta`, and `sentinellite demo` produced 3 synthetic events
and 3 alerts. `sentinellite dashboard export` saved `reports/dashboard.html`; the HTML
contained `SentinelLite AI Local Dashboard` and rows for `AUTH-001`, `AUTH-002`, and
`AUTH-003`. This confirms the synthetic report-to-dashboard workflow, not endpoint
security effectiveness.

## Local Static Dashboard

The published release includes:

```bash
sentinellite dashboard export --reports-dir reports --output reports/dashboard.html --limit 25
```

`sentinellite dashboard export` reads existing local JSON reports only and generates one
standalone static HTML file. It prints the saved path and leaves source reports unchanged.
The defaults are `reports`, `reports/dashboard.html`, and a display limit of 25.

The dashboard presents report and alert totals, highest displayed severity, report time,
severity/rule/module breakdowns, and alert/report tables. It escapes report-derived text
and omits raw evidence. Invalid or incompatible reports are skipped; an empty or missing
report directory produces a dashboard explaining that no reports were found.

There is no server, browser auto-open, external scripts/assets, network requests, live
monitoring, or automatic remediation. The exporter performs no endpoint observation or
scanning. Open the saved HTML file manually for offline review.

## Safe Demo and Installation Checks

```bash
sentinellite doctor
sentinellite demo
sentinellite dashboard export
sentinellite reports list
sentinellite reports show <REPORT_PATH>
```

`doctor` checks local installation readiness only. `demo` uses synthetic fixture data only:
it reads no real logs, performs no process/network/file observation, and sends no network
traffic. Replace `<REPORT_PATH>` with the saved path printed by `demo`. The dashboard then
reads the saved local JSON reports; it does not generate new endpoint observations.

The existing JSON report schema is unchanged. See the [demo guide](demo-guide.md) and
[release checklist](release-checklist.md) for the walkthrough and reusable release validation gates.

## ARM-SecNet Lab 03 Evidence

[Recorded Lab 03 evidence](https://github.com/kavisara-samarakoon/arm-secnet/blob/d3d9a7153939f58ebe9c08215ea4211c65472595/docs/evidence/v1.1-sentinellite-dashboard.md)
was completed separately in ARM-SecNet on one Ubuntu 26.04 LTS `aarch64` VM with Python
3.14.4. That run validated the dashboard workflow using SentinelLite source commit
`d1775f0ca09d714f5ed9d681af90f216c1c39e8e` from `main`, before this version bump; the tested
source displayed `SentinelLite AI v1.1.0-beta` and included the post-release dashboard command.

| Recorded check | Result |
| --- | --- |
| Doctor | 10 passed, 0 warnings, 0 failed |
| Synthetic demo | 3 synthetic events, 3 alerts |
| Report review | `AUTH-001`, `AUTH-002`, `AUTH-003`; low 1, medium 2 |
| Dashboard export | `reports/dashboard.html` |
| Local browser review | 1 loaded report, 3 alerts shown, highest severity medium; breakdowns and alert/report tables |
| ARM-SecNet documentation/evidence validation after merge | 29 passed, 0 warnings, 0 failures |

The 29 checks validate ARM-SecNet documentation and evidence files. They are separate from
SentinelLite's automated test suite and the recorded VM command results. This evidence
applies to that specific VM and source commit only: it does not prove universal ARM64
compatibility or validation of the exact published release commit.

ARM-SecNet provides the ARM64 lab environment. SentinelLite AI provides the optional local
defensive observation, report-review, and static dashboard CLI. They remain separate
repositories with no runtime dependency. See the [integration guide](integrations/arm-secnet.md).

## Defensive Scope and Limitations

This is not a production EDR release. SentinelLite AI is a beta-stage, local, on-demand,
defensive endpoint observation and report-review CLI, not antivirus, a SIEM/SOC platform,
a malware remover, or an enterprise security platform. Alerts do not prove malware or
compromise, and the lab evidence makes no production protection claim.

- No real AI or LLM execution; explanations remain deterministic local templates.
- No daemon, scheduler, background service, or live monitoring.
- No external notification delivery or network requests.
- No active network scanning, public scanning, packet sending, or exploitation.
- No automatic remediation, malware removal, firewall changes, or process killing.
- No PyPI publishing as part of this milestone.

The dashboard is a static report viewer with no live updates. Reports and exports remain
local artifacts that require appropriate handling when they contain host-derived data.

## Release History

The previous published milestone is [v1.1.0-beta](release-notes-v1.1.0-beta.md).
Its historical publication details remain unchanged; they do not describe this release.
