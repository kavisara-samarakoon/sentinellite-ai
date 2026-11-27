# SentinelLite AI — Cloud VM Workload Validation Procedure

This procedure validates the published `v1.3.0-beta` release (`1.3.0b0`) on an authorized
Ubuntu LTS virtual machine (planned Azure x86-64 via ARM-SecNet, or deferred UTM ARM64)
using a fixture-first, least-privilege workflow.

> [!NOTE]
> For deferred UTM Ubuntu ARM64 validation ([Issue #17](https://github.com/kavisara-samarakoon/sentinellite-ai/issues/17)),
> this shared workload procedure covers exact-wheel runtime checks only. It does **not**
> replace Issue #17's additional exact-source `pytest` suite, `ruff`, and ARM64 acceptance
> requirements.

## Release Provenance

- **GitHub pre-release:** [v1.3.0-beta](https://github.com/kavisara-samarakoon/sentinellite-ai/releases/tag/v1.3.0-beta)
- **Tag object SHA:** `b13fe9c6030b2422ab45a7df8060f133fa452f8a`
- **Tag target commit:** `bf84cf93b40fa73f6489cc4312b2769bcb93204f`
- **CLI version:** `1.3.0-beta` (`SentinelLite AI v1.3.0-beta`)
- **Package version:** `1.3.0b0`

| Asset | Expected SHA-256 |
| --- | --- |
| `sentinellite_ai-1.3.0b0-py3-none-any.whl` | `02fb7409a3e071d561700b9783af2136307669aaa332260d4324e20ea3c0dab3` |
| `sentinellite_ai-1.3.0b0.tar.gz` | `c17e285ccf6e99cad8c8e6e2f5ef284da542adc6312fd4f9fd843128df0f128d` |
| `SHA256SUMS.txt` | `9c18c75a257c7c7d0668200c0a23b419f781041055bef64c8a93f9f25ec24fc4` |

## ARM-SecNet Infrastructure Contract (ARM-C0 / ARM-C1)

SentinelLite AI has **no runtime dependency** on ARM-SecNet, Terraform, or Azure credentials
and does **not** provision its own VM. The host VM must provide:

1. Supported Ubuntu LTS image with confirmed guest architecture (`x86_64` or `aarch64`).
2. Python `3.11` or newer with `venv` support (`python3-venv` pre-installed by admin/image).
3. Authorized normal (non-root) user account; never run SentinelLite as `root`.
4. Sufficient memory and disk capacity for venv creation, wheel installation, and temp outputs.
5. Approved artifact and PyPI dependency acquisition method (wheel + `SHA256SUMS.txt` verified).
6. Private writable working/output directory (`umask 077`).
7. Secure administrative access managed by ARM-SecNet; **no public dashboard HTTP port**.

## Least-Privilege & Privacy Boundaries

- Set `umask 077` before creating validation directories or running commands.
- Use **separate fresh output directories** for each workload (`demo-reports`, `auth-reports`,
  `fim-scan-reports`, `fim-unchanged-reports`, `fim-changed-reports`).
- Do **not** scan `/var/log/auth.log` or `/var/log/secure` during workload validation; use
  bundled fixtures only.
- Never commit reports, baselines, notifications, credentials, or VM evidence to Git.

## Stage 1 — Approved Artifact & Fixture Acquisition (Separate from Execution)

Before running the workload procedure, stage two read-only input directories using your
approved acquisition channel (do **not** modify original artifacts):

1. **`ARTIFACT_DIR`**: Directory containing `sentinellite_ai-1.3.0b0-py3-none-any.whl` and
   `SHA256SUMS.txt` (and optionally `sentinellite_ai-1.3.0b0.tar.gz` if sdist is acquired).
2. **`FIXTURE_REPO_DIR`**: Clean source checkout at the exact published commit
   `bf84cf93b40fa73f6489cc4312b2769bcb93204f` (the published wheel and sdist do **not**
   contain repository test fixtures).

## Stage 2 — Preflight, Provenance Enforcement, & Synthetic/Fixture Validation

Run in **Bash** inside the authorized Ubuntu VM as a **normal user** (`EXPECTED_ARCH` must be
explicitly set to `x86_64` or `aarch64`):

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077

# --- Required caller inputs ---
: "${ARTIFACT_DIR:?Set ARTIFACT_DIR to the approved release artifact directory}"
: "${FIXTURE_REPO_DIR:?Set FIXTURE_REPO_DIR to the checkout at bf84cf93b40fa73f6489cc4312b2769bcb93204f}"
: "${EXPECTED_ARCH:?Set EXPECTED_ARCH to x86_64 or aarch64}"

# --- 1. Environment preflight (fail closed; no apt/sudo) ---
[ -n "${BASH_VERSION:-}" ] || { echo "FAIL: Bash is required." >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo "FAIL: Do not run as root." >&2; exit 1; }
[ "$(uname -s)" = "Linux" ] || { echo "FAIL: Linux is required." >&2; exit 1; }
grep -qi '^ID=ubuntu$' /etc/os-release || { echo "FAIL: Ubuntu Linux is required." >&2; exit 1; }
case "$EXPECTED_ARCH" in
  x86_64|aarch64) ;;
  *) echo "FAIL: EXPECTED_ARCH must be x86_64 or aarch64." >&2; exit 1 ;;
esac
[ "$(uname -m)" = "$EXPECTED_ARCH" ] || { echo "FAIL: Expected arch $EXPECTED_ARCH, got $(uname -m)." >&2; exit 1; }
python3 -c 'import sys, venv; assert sys.version_info >= (3, 11)' || { echo "FAIL: Python >=3.11 with venv is required." >&2; exit 1; }
python3 -c 'import ensurepip' >/dev/null 2>&1 || { echo "FAIL: python3-venv/ensurepip is missing; ask admin to install it." >&2; exit 1; }

uname -a
uname -m
cat /etc/os-release
python3 --version

# --- 2. Fixture checkout identity & exact checksum enforcement (fail closed) ---
fixture_head="$(git -C "$FIXTURE_REPO_DIR" rev-parse HEAD)"
[ "$fixture_head" = "bf84cf93b40fa73f6489cc4312b2769bcb93204f" ] || {
  echo "FAIL: Fixture repo HEAD is $fixture_head, expected bf84cf93b40fa73f6489cc4312b2769bcb93204f" >&2
  exit 1
}

WHEEL_FILE="$ARTIFACT_DIR/sentinellite_ai-1.3.0b0-py3-none-any.whl"
SUMS_FILE="$ARTIFACT_DIR/SHA256SUMS.txt"
SDIST_FILE="$ARTIFACT_DIR/sentinellite_ai-1.3.0b0.tar.gz"
EXPECTED_WHEEL_SHA="02fb7409a3e071d561700b9783af2136307669aaa332260d4324e20ea3c0dab3"
EXPECTED_SUMS_SHA="9c18c75a257c7c7d0668200c0a23b419f781041055bef64c8a93f9f25ec24fc4"
EXPECTED_SDIST_SHA="c17e285ccf6e99cad8c8e6e2f5ef284da542adc6312fd4f9fd843128df0f128d"

[ -f "$WHEEL_FILE" ] || { echo "FAIL: Missing wheel: $WHEEL_FILE" >&2; exit 1; }
[ -f "$SUMS_FILE" ] || { echo "FAIL: Missing SHA256SUMS.txt: $SUMS_FILE" >&2; exit 1; }

printf '%s  %s\n' "$EXPECTED_SUMS_SHA" "$SUMS_FILE" | sha256sum -c -
printf '%s  %s\n' "$EXPECTED_WHEEL_SHA" "$WHEEL_FILE" | sha256sum -c -
grep -Fx "${EXPECTED_WHEEL_SHA}  sentinellite_ai-1.3.0b0-py3-none-any.whl" "$SUMS_FILE" >/dev/null || {
  echo "FAIL: SHA256SUMS.txt does not match expected wheel digest." >&2
  exit 1
}
if [ -f "$SDIST_FILE" ]; then
  printf '%s  %s\n' "$EXPECTED_SDIST_SHA" "$SDIST_FILE" | sha256sum -c -
fi

# --- 3. Isolated venv installation & provenance ---
# Clear inherited Python path vars so installed wheel is tested without source-tree leakage.
unset PYTHONPATH PYTHONHOME
WORK_ROOT="$(mktemp -d /tmp/sentinellite-vm-val.XXXXXX)"
VENV_DIR="$WORK_ROOT/venv"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install "$WHEEL_FILE"
"$VENV_DIR/bin/python" -m pip check
# Note: sentinellite-ai 1.3.0b0 wheel is immutable; transitive dependency versions are not locked.
"$VENV_DIR/bin/python" -m pip list --format=freeze

(
  cd "$WORK_ROOT"
  "$VENV_DIR/bin/python" -c 'from importlib import metadata; from sentinellite import __version__; assert metadata.version("sentinellite-ai") == "1.3.0b0"; assert __version__ == "1.3.0-beta"'
  test "$("$VENV_DIR/bin/sentinellite" --version)" = "SentinelLite AI v1.3.0-beta"
  test "$("$VENV_DIR/bin/python" -m sentinellite --version)" = "SentinelLite AI v1.3.0-beta"
  "$VENV_DIR/bin/sentinellite" --help >/dev/null
  "$VENV_DIR/bin/sentinellite" >/dev/null
)

# --- 4. Doctor, synthetic demo, and static dashboard export ---
DEMO_DIR="$WORK_ROOT/demo-reports"
DASH_HTML="$WORK_ROOT/dashboard.html"
"$VENV_DIR/bin/sentinellite" doctor --output-dir "$DEMO_DIR"
"$VENV_DIR/bin/sentinellite" demo --output-dir "$DEMO_DIR"
"$VENV_DIR/bin/sentinellite" dashboard export --reports-dir "$DEMO_DIR" --output "$DASH_HTML" --limit 25

"$VENV_DIR/bin/python" - "$DEMO_DIR" "$DASH_HTML" <<'PY'
import sys
from pathlib import Path
from sentinellite.reporting.schema import ReportContract
from sentinellite.reporting.validation import parse_report_json

demo_reports = sorted(Path(sys.argv[1]).glob("*.json"))
assert len(demo_reports) == 1, f"Expected 1 demo report, got {demo_reports}"
report = parse_report_json(demo_reports[0].read_bytes())
assert report.contract is ReportContract.SCHEMA_V1
assert type(report.schema_version) is int and report.schema_version == 1
report_data = report.to_dict()
assert report_data["alert_count"] == 3 and len(report_data["alerts"]) == 3
assert [a["rule_id"] for a in report_data["alerts"]] == ["AUTH-001", "AUTH-002", "AUTH-003"]

html = Path(sys.argv[2]).read_text(encoding="utf-8")
for marker in ("SentinelLite AI Local Dashboard", "AUTH-001", "AUTH-002", "AUTH-003"):
    assert marker in html, f"Missing dashboard marker: {marker}"
assert "<script" not in html.lower()
print("DEMO_AND_DASHBOARD_OK")
PY
# Note: On headless VMs, HTML generation/content checks do not verify interactive browser rendering.

# --- 5. Auth fixture, schema-v1 + legacy validation, review, and notification export ---
AUTH_DIR="$WORK_ROOT/auth-reports"
NOTIF_DIR="$WORK_ROOT/notifications"
mkdir -p "$NOTIF_DIR"
UBUNTU_FIXTURE="$FIXTURE_REPO_DIR/examples/auth_logs/sample_ubuntu_auth.log"
LEGACY_FIXTURE="$FIXTURE_REPO_DIR/tests/fixtures/report_schema/legacy_unversioned_alert.json"

(
  cd "$WORK_ROOT"
  "$VENV_DIR/bin/sentinellite" auth-sources list
  "$VENV_DIR/bin/sentinellite" scan-auth "$UBUNTU_FIXTURE" --output-dir "$AUTH_DIR"
  "$VENV_DIR/bin/sentinellite" reports list --report-dir "$AUTH_DIR"
)

auth_reports=( "$AUTH_DIR"/*.json )
[ "${#auth_reports[@]}" -eq 1 ] || { echo "FAIL: Expected 1 auth report" >&2; exit 1; }
REPORT_PATH="${auth_reports[0]}"
"$VENV_DIR/bin/sentinellite" reports show "$REPORT_PATH"

before_report_sha="$(sha256sum "$REPORT_PATH" | awk '{print $1}')"
before_legacy_sha="$(sha256sum "$LEGACY_FIXTURE" | awk '{print $1}')"
NOTIF_PATH="$NOTIF_DIR/alert-summary.json"
"$VENV_DIR/bin/sentinellite" reports export-notification "$REPORT_PATH" --output "$NOTIF_PATH"
after_report_sha="$(sha256sum "$REPORT_PATH" | awk '{print $1}')"
after_legacy_sha="$(sha256sum "$LEGACY_FIXTURE" | awk '{print $1}')"
test "$before_report_sha" = "$after_report_sha"
test "$before_legacy_sha" = "$after_legacy_sha"

"$VENV_DIR/bin/python" - "$REPORT_PATH" "$NOTIF_PATH" "$LEGACY_FIXTURE" <<'PY'
import json
import sys
from pathlib import Path
from sentinellite.reporting.schema import ReportContract
from sentinellite.reporting.validation import parse_report_json

v1 = parse_report_json(Path(sys.argv[1]).read_bytes())
assert v1.contract is ReportContract.SCHEMA_V1
assert type(v1.schema_version) is int and v1.schema_version == 1
v1_data = v1.to_dict()
assert v1_data["alert_count"] == 3 and len(v1_data["alerts"]) == 3
assert [a["rule_id"] for a in v1_data["alerts"]] == ["AUTH-001", "AUTH-002", "AUTH-003"]

notif = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert set(notif) == {
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
assert type(notif["schema_version"]) is int and notif["schema_version"] == 1
assert notif["output_type"] == "sentinellite_notification_summary"
assert set(notif["source"]) == {"report_id", "generated_at"}
assert notif["alert_count"] == 3
assert notif["included_alert_count"] == 3
assert notif["omitted_alert_count"] == 0
assert len(notif["alerts"]) == 3
for item in notif["alerts"]:
    assert set(item) == {"rule_id", "category", "severity", "risk_score", "risk_level"}

legacy = parse_report_json(Path(sys.argv[3]).read_bytes())
assert legacy.contract is ReportContract.LEGACY_UNVERSIONED
assert legacy.schema_version is None
assert "schema_version" not in legacy.to_dict()
print("AUTH_SCHEMA_LEGACY_NOTIF_OK")
PY

# --- 6. Disposable selected-file integrity and baseline comparison (separate output dirs) ---
FIM_SCAN_DIR="$WORK_ROOT/fim-scan-reports"
FIM_UNCHANGED_DIR="$WORK_ROOT/fim-unchanged-reports"
FIM_CHANGED_DIR="$WORK_ROOT/fim-changed-reports"
TARGET_FILE="$WORK_ROOT/disposable-target.txt"
BASELINE_FILE="$WORK_ROOT/baseline.json"

printf "initial-content\n" > "$TARGET_FILE"
"$VENV_DIR/bin/sentinellite" scan-files "$TARGET_FILE" --output-dir "$FIM_SCAN_DIR"
"$VENV_DIR/bin/sentinellite" baseline-files "$TARGET_FILE" --baseline-path "$BASELINE_FILE"

before_baseline_sha="$(sha256sum "$BASELINE_FILE" | awk '{print $1}')"
before_target_sha="$(sha256sum "$TARGET_FILE" | awk '{print $1}')"
"$VENV_DIR/bin/sentinellite" scan-files-baseline --baseline-path "$BASELINE_FILE" --output-dir "$FIM_UNCHANGED_DIR"
test "$before_baseline_sha" = "$(sha256sum "$BASELINE_FILE" | awk '{print $1}')"
test "$before_target_sha" = "$(sha256sum "$TARGET_FILE" | awk '{print $1}')"

printf "modified-content\n" > "$TARGET_FILE"
before_modified_sha="$(sha256sum "$TARGET_FILE" | awk '{print $1}')"
"$VENV_DIR/bin/sentinellite" scan-files-baseline --baseline-path "$BASELINE_FILE" --output-dir "$FIM_CHANGED_DIR"
test "$before_baseline_sha" = "$(sha256sum "$BASELINE_FILE" | awk '{print $1}')"
test "$before_modified_sha" = "$(sha256sum "$TARGET_FILE" | awk '{print $1}')"

"$VENV_DIR/bin/python" - "$FIM_SCAN_DIR" "$FIM_UNCHANGED_DIR" "$FIM_CHANGED_DIR" <<'PY'
import sys
from pathlib import Path
from sentinellite.reporting.validation import parse_report_json

for d in sys.argv[1:]:
    reports = sorted(Path(d).glob("*.json"))
    assert len(reports) == 1, f"Expected 1 report in {d}, got {reports}"

unchanged = parse_report_json(next(Path(sys.argv[2]).glob("*.json")).read_bytes()).to_dict()
assert unchanged["alert_count"] == 0 and len(unchanged["alerts"]) == 0

changed = parse_report_json(next(Path(sys.argv[3]).glob("*.json")).read_bytes()).to_dict()
assert changed["alert_count"] >= 1
assert "FIM-004" in {a["rule_id"] for a in changed["alerts"]}
print("FIM_BASELINE_OK")
PY

echo "RETAINED_WORKSPACE=$WORK_ROOT"
```

## Stage 3 — Opt-In Authorized Host Observation (Manual Only)

Do **not** run `scan-process` or `scan-network` automatically as part of synthetic validation.
Process arguments, usernames, paths, and connection metadata may contain sensitive operational
context. Under non-root `/proc` permissions, restricted fields (`exe`, `cmdline`, `pid`,
`process_name`) may appear as `None`/`[]` or empty connection lists; this reflects expected
least-privilege visibility rather than complete collector visibility.

Run only when explicitly authorized on the target VM:

```bash
"$VENV_DIR/bin/sentinellite" scan-process --output-dir "$WORK_ROOT/proc-reports"
"$VENV_DIR/bin/sentinellite" scan-network --output-dir "$WORK_ROOT/net-reports"
```

## Stage 4 — Optional Path-Guarded Cleanup (After Evidence Acceptance)

Evidence in `$WORK_ROOT` is retained for local inspection. Do **not** publish raw operational
reports or sensitive host evidence. After recording redacted evidence, remove the private
workspace with a path-guarded check:

```bash
case "${WORK_ROOT:-}" in
  /tmp/sentinellite-vm-val.*) rm -rf -- "$WORK_ROOT" ;;
  *) echo "Refusing cleanup: unexpected WORK_ROOT=${WORK_ROOT:-unset}" >&2; exit 1 ;;
esac
```
