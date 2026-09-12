# SentinelLite AI v1.2.0-beta — Local Dashboard and ARM-SecNet Lab Validation

## Release candidate status

- GitHub release: pending
- Tag: pending
- Wheel/sdist hashes: pending final build

The prepared source version is `1.2.0-beta`; normalized Python package metadata is
`1.2.0b0`. This is a release candidate, not a published GitHub release. Final publication
time, release commit, and asset digests will be recorded after release creation.
SentinelLite AI is not published to PyPI.

## Local Static Dashboard

The release candidate includes:

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
[release checklist](release-checklist.md) for the walkthrough and candidate validation gates.

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
compatibility or validation of the exact release candidate commit.

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
Its historical publication details remain unchanged; they do not describe this candidate.
