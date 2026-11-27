# SentinelLite AI — Privacy-Preserving Offline Telemetry Export Design (SENT-C2)

This document defines the offline telemetry export contract, component reuse assessment,
resource limits, provenance rules, and proposed future Azure ingestion architecture for
SentinelLite AI.

- **Implemented locally (SENT-C2-P03):** `src/sentinellite/reporting/telemetry.py`,
  `src/sentinellite/reporting/telemetry_io.py`, and
  `sentinellite reports export-telemetry REPORT_PATH --output OUTPUT_PATH`.
- **Retained design evidence:** `experiments/sent_c2/` (isolated prototype, not imported by
  or packaged into `sentinellite`).
- **Not implemented:** Azure ingestion, HTTP clients, credentials, and the Stage 4 optional
  separate Azure companion/adapter remain future plans only.

## 1. Existing Component Reuse Assessment

| Component | Reusable Pattern | Limitations & Required Telemetry Adjustments |
| --- | --- | --- |
| [schema.py](../../src/sentinellite/reporting/schema.py) | `SEVERITY_VALUES`, `RISK_LEVEL_VALUES`, `ReportContract`, `ReportValidationOutcome`. | Does not declare a closed `rule_id` allowlist or telemetry contract constants; telemetry adds its own frozen `TELEMETRY_ALLOWED_RULE_IDS` and `TELEMETRY_SCHEMA_VERSION = 1`. |
| [validation.py](../../src/sentinellite/reporting/validation.py) | `parse_report_json()` strict UTF-8, `_unique_object` (duplicate key rejection), `_reject_constant` (`NaN`/`Infinity`), `_finite_float`, strict integer/bool separation, and `ValidatedReport` defensive copies. | Does not enforce byte-size or nesting limits, and permits arbitrary non-empty `rule_id` and arbitrary `category` strings. Telemetry must wrap `parse_report_json()` with pre-parse byte limits and post-parse closed `rule_id` allowlisting. |
| [review.py](../../src/sentinellite/reporting/review.py) | `MAX_REPORT_SIZE_BYTES = 2 * 1024 * 1024`, safe error sanitization (hiding user-supplied evidence keys from diagnostics). | `load_review_report()` uses `path.stat()` followed by `path.open("rb")`, which follows symlinks and has a TOCTOU window. Telemetry file reading must open with `O_RDONLY \| O_NOFOLLOW` (where available) and `os.fstat()` on the open descriptor. |
| [notification.py](../../src/sentinellite/reporting/notification.py) | `write_notification_summary()` private file creation (`0o600`, `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `fstat` identity check, partial-output cleanup). | **Not safe for external telemetry:** notification summaries copy `source.report_id`, `source.generated_at`, `risk_score`, unvalidated `rule_id`, and arbitrary `category` strings. |
| [rules.py](../../src/sentinellite/detection/rules.py) | Authoritative bundled rule definitions (`AUTH-001..003`, `PROC-001..003`, `NET-001..003`, `FIM-001..008`). | Serves as the closed source of truth for telemetry `rule_id` allowlisting in v1. |

## 2. Minimum Telemetry Contract (`sentinellite_telemetry` v1)

A telemetry export is a separate artifact from alert reports and notification summaries.
It aggregates scored alerts from **one** explicitly selected, validated alert report.
It never recomputes source alert risk scores or reinterprets historical detection results.

### Top-Level Fields (Exact Allowlist)

| Field | Type | Requirement |
| --- | --- | --- |
| `schema_version` | `int` (not `bool` or `float`) | Exact integer `1`. |
| `output_type` | `str` | Fixed literal `"sentinellite_telemetry"`. |
| `export_id` | `str` | Generated canonical lowercase UUIDv4 (`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`), never derived from source report contents. |
| `exported_at` | `str` | Generated canonical UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.ffffffZ`), never copied from source event or report time. |
| `alert_count` | `int` (not `bool` or `float`) | Bounded nonnegative integer (`0 <= alert_count <= 1000`), equal to `sum(g["count"] for g in groups)`. |
| `groups` | `list[dict]` | Deterministically sorted list (`0 <= len(groups) <= 128`) of unique aggregation groups. |

### Group Entry Fields (Exact Allowlist)

Each object in `groups` contains **exactly** four keys:

| Field | Type | Requirement |
| --- | --- | --- |
| `rule_id` | `str` | Member of the closed v1 rule-ID allowlist (17 bundled rules). |
| `severity` | `str` | Member of `{"info", "low", "medium", "high", "critical"}`. |
| `risk_level` | `str` | Member of `{"info", "low", "medium", "high", "critical"}`. |
| `count` | `int` (not `bool` or `float`) | Positive integer (`1 <= count <= 1000`). |

### Sufficiency Assessment

`{rule_id, severity, risk_level, count}` is **sufficient** for cloud-learning and
detection-triage volume analysis because each allowlisted `rule_id` already maps 1:1 to a
known bundled detection rule and module category in [rules.py](../../src/sentinellite/detection/rules.py).
Omitting `category`, `risk_score`, `report_id`, `generated_at`, and free-text fields avoids
unnecessary operational context and prevents arbitrary string injection.

### Closed v1 Rule-ID Allowlist

- Authentication: `AUTH-001`, `AUTH-002`, `AUTH-003`
- Process: `PROC-001`, `PROC-002`, `PROC-003`
- Network: `NET-001`, `NET-002`, `NET-003`
- File Integrity: `FIM-001`, `FIM-002`, `FIM-003`, `FIM-004`, `FIM-005`, `FIM-006`, `FIM-007`, `FIM-008`

### Invariants, Empty Reports, and Serialization

- **Unique aggregation keys & deterministic ordering:** Keys `(rule_id, severity, risk_level)`
  must be unique within `groups` and sorted lexicographically by `(rule_id, severity, risk_level)`.
- **Empty report behavior:** An input report with `alert_count == 0` and `alerts == []`
  produces a valid telemetry export with `alert_count: 0` and `groups: []`.
- **Rejection rules:** Unknown top-level or group fields, unknown or malicious `rule_id`
  values, zero or negative `schema_version` (`incompatible`), positive future
  `schema_version` (`unsupported-schema`), invalid scalar types (requiring exact JSON-native
  types and rejecting `bool` for `int`), invalid calendar dates/times/offsets in `exported_at`,
  invalid enums, duplicate groups, and mismatched `alert_count` are rejected fail-closed.
- **Exception confidentiality:** Telemetry wraps canonical parser exceptions using
  `raise TelemetryError(...) from None`, returning fixed, sanitized diagnostics without
  original parser exception chains, raw input, sensitive paths, or traceback locals.
  Sanitized public diagnostics do not protect against privileged debugging or process-memory
  inspection.
- **Identity/timestamp overrides:** Generated UTC `exported_at` and UUIDv4 `export_id`
  are automatic; no user-controlled identity or timestamp options may be added to the
  proposed production CLI. Overrides are reserved strictly for deterministic prototype tests.
- **Distinct error outcomes:** `malformed`, `incompatible`, `unsupported-schema`,
  `unsupported-rule`, `limit-exceeded`, and `output-error`.
- **Canonical serialization:** UTF-8 JSON (`sort_keys=True`, `indent=2`, trailing `\n`,
  `allow_nan=False`).

## 3. Resource Limits & Boundary Semantics

All limits fail closed rather than silently truncating:

| Resource | Limit | Boundary Semantics |
| --- | --- | --- |
| Reports per export | `1` | One explicitly selected file path; no directory discovery. |
| Input file size | `2 MiB` (`2,097,152` bytes) | `<= 2,097,152` accepted; `> 2,097,152` rejected (`limit-exceeded`). |
| JSON container nesting depth | `64` | Root container counts as depth `1`; `<= 64` accepted; `> 64` rejected (`limit-exceeded`). |
| Input alerts | `1,000` alerts | `<= 1,000` accepted; `> 1,000` rejected (`limit-exceeded`). |
| Aggregation groups | `128` groups | `<= 128` accepted; `> 128` rejected (`limit-exceeded`). |
| Serialized output & saved telemetry | `64 KiB` (`65,536` bytes) | UTF-8 encoded bytes `<= 65,536` accepted; `> 65,536` rejected (`limit-exceeded`). |

Notes and residual assumptions:
- A `2 MiB` input cap does **not** guarantee a `2 MiB` peak memory limit during Python JSON
  decoding.
- **Bounded nesting policy:** Without duplicating `parse_report_json()`, telemetry runs a
  lightweight string-aware preflight container depth scanner (`MAX_JSON_NESTING_DEPTH = 64`)
  on bounded (`<= 2 MiB` source or `<= 64 KiB` saved telemetry) UTF-8 text before calling
  `parse_report_json()` or `json.loads()`, and catches `RecursionError` as sanitized
  `incompatible`.
- Under the closed 17-rule contract and `128`-group cap, the largest feasible valid
  telemetry payload is ~13 KiB, so `64 KiB` is unreachable without reducing the test limit.

## 4. Production Filesystem Specification, Source Preservation, & Export Identity

- **Source preservation:** Input reports are opened read-only and remain byte-for-byte
  unchanged; source reports are never automatically deleted.
- **Input reader requirements (implemented in `telemetry_io.py`):**
  - Open with `O_RDONLY | O_NONBLOCK | O_NOFOLLOW` via a pinned `0700` owner-owned directory
    descriptor (preventing FIFO-open hangs and final-component symlink following), failing
    closed on unsupported required safety primitives or `NotImplementedError` rather than
    silently weakening guarantees.
  - Verify `S_ISREG`, effective-user ownership, private source permissions (`mode & 0o077 == 0`,
    preferring `0600`), and size via `os.fstat()` before and after bounded reading of at most
    `MAX_INPUT_BYTES + 1` bytes (post-read consistency checks cover device, inode, ownership,
    mode, size, mtime, and ctime). Existing source reports are never `chmod`ed or rewritten,
    and there is no public `max_bytes` bypass exceeding `MAX_INPUT_BYTES`.
  - POSIX mode checks assume trusted ancestor directories, trusted ACL configurations, and
    trusted filesystems; they do not universally prove absence of alternative access grants
    (for example, POSIX ACLs) or protect against arbitrary equivalent-privilege processes.
- **Output writer requirements (implemented in `telemetry_io.py`):**
  - `write_telemetry_file()` strictly validates and canonically serializes the payload
    before any filesystem mutation, refusing invalid payloads before creating a destination
    or temporary file.
  - Explicit output destination inside a pinned `0700` owner-owned private directory;
    rejects pre-existing destinations before temporary creation.
  - Creates a `0600` same-directory temporary file with `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`,
    writes complete bytes, `fsync`s the file, publishes via atomic no-clobber `os.link`
    using directory descriptors, unlinks the temporary name, and `fsync`s the directory.
  - Pre-publication failures unlink the temporary file and preserve `published=False`
    (explicitly reporting possible private temporary-file residue if cleanup also fails);
    post-publication cleanup or directory-fsync failures report `published=True` and never
    delete the published file. Crash windows can leave private temporary-file residue.
- **Saved telemetry parser & export identity:**
  - `parse_telemetry_json()` validates saved telemetry UTF-8 bytes (`<= 64 KiB`), rejects
    duplicate keys before dict validation, rejects nonfinite numbers, and preserves `export_id`.
  - Re-uploading the same saved export preserves `export_id`; independent re-exports
    receive different UUIDv4s.
  - Telemetry does **not** promise exactly-once delivery, cryptographic authenticity, or
    semantic deduplication across independently regenerated exports, and never hashes raw
    source data into externally visible IDs.

## 5. Proposed Future Azure Ingestion Architecture (Design Only)

- **Boundary:** SentinelLite AI core remains local-only. Any future Azure upload belongs in
  an optional, separate companion/adapter outside the core local CLI.
- **Infrastructure & Identity:** ARM-SecNet owns Azure resource provisioning. Authentication
  uses **Managed Identity** only (no long-lived shared keys or user credentials stored in
  SentinelLite), with **DCR-scoped Monitoring Metrics Publisher** RBAC authorization.
- **Ingestion Path:** Direct Data Collection Rule (DCR) ingestion endpoint (using a Data
  Collection Endpoint only when required by network/private-link topology) targeting an
  approved Log Analytics custom table (`*_CL`) and custom input stream.
- **Record Shape & Duplicate-Aware Queries:** Prefer **one stored record per export
  envelope** with `groups` represented as structured data (`dynamic`). Duplicate-aware KQL
  queries must deduplicate export records by `export_id` **before** expanding `groups`. If
  flattened group rows are ever selected later, `export_id` alone cannot distinguish every
  group row; conflicting payloads with the same `export_id` must not be silently treated as
  identical.
- **Mapping & Time Semantics:** Explicit DCR transform mapping `export_id`, `exported_at`
  (mapped to `TimeGenerated`), `schema_version`, `alert_count`, and `groups`.
- **Operator Safety Gates:** Synthetic-first ingestion; default `--dry-run` behavior;
  destination preview and explicit operator confirmation before transmission; bounded batches,
  bounded retries, and explicit cost, retention, access-control, and teardown gates.
- **Official Microsoft References:**
  - [Logs Ingestion API overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
  - [Authenticate with Microsoft Entra / Managed Identity for Logs Ingestion](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/register-app-for-token)
  - [Azure Monitor service limits](https://learn.microsoft.com/en-us/azure/azure-monitor/service-limits)
