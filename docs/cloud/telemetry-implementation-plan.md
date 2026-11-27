# SentinelLite AI — Telemetry Implementation Plan (SENT-C2)

Stages 1–3 below are **implemented locally** in SENT-C2-P03. Stage 4 (optional separate
Azure companion/adapter) remains **unimplemented** and out of scope for core SentinelLite.

## Stage 1 — Core Telemetry Schema, Projection, & Validator (Implemented)

- **Scope:** Add `src/sentinellite/reporting/telemetry.py` (or equivalent module) declaring
  `TELEMETRY_SCHEMA_VERSION = 1`, `TELEMETRY_OUTPUT_TYPE = "sentinellite_telemetry"`,
  closed `TELEMETRY_ALLOWED_RULE_IDS`, resource limit constants, canonical `project_telemetry()`,
  `validate_telemetry_data()`, and `serialize_telemetry_json()`.
- **Acceptance Criteria:**
  - Reuses `parse_report_json()` without duplicating JSON report parsing.
  - Enforces all exact field allowlists, closed rule/enum checks, `bool` rejection for `int`,
    `0..1000` alert limit, `0..128` group limit, and `64 KiB` output limit.
  - Deterministic sorting and serialization verified with fixed `export_id` / `exported_at`.

## Stage 2 — Hardened Local Reader & Private Writer (Implemented)

- **Scope:** Implement `O_RDONLY | O_NONBLOCK | O_NOFOLLOW` + `os.fstat()` bounded (`<= 2 MiB`)
  report reading and trusted-private-directory no-clobber (`0o600`) output writer with
  temporary-file / failure cleanup and byte-for-byte source preservation.
- **Acceptance Criteria:**
  - FIFO/special-file timeout prevention, symlinks, directories, and `> 2 MiB` inputs fail
    closed before parse without silently weakening safety primitives.
  - Existing output destinations are never overwritten; write failures leave no partial file.
  - Source report SHA-256 is unchanged; residual crash/parent-dir risks documented.

## Stage 3 — Local CLI Integration & Regression Suite (Implemented)

- **Scope:** Add `sentinellite reports export-telemetry REPORT_PATH --output OUTPUT_PATH`
  (offline only, no network calls) and update [docs/data-contracts.md](../data-contracts.md).
- **Acceptance Criteria:**
  - Full production pytest suite (`tests/`), separate retained prototype suite
    (`experiments/sent_c2/test_telemetry_prototype.py`), Ruff, `pip check`, and
    `git diff --check` pass on macOS and Ubuntu CI.
  - Sanitized CLI diagnostics never echo untrusted `evidence` or sensitive fixture values.

## Stage 4 — Optional Separate Azure Companion (Future Milestone)

- **Scope:** Separate companion/adapter outside SentinelLite AI core using ARM-SecNet
  Managed Identity + DCR-scoped Monitoring Metrics Publisher + custom Log Analytics table.
- **Acceptance Criteria:**
  - Default `--dry-run`, destination preview, explicit operator authorization, synthetic-first
    ingestion, bounded batches/retries, duplicate-aware KQL queries, and verified teardown.
