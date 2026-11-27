# SentinelLite AI — Offline Telemetry Threat Model (SENT-C2)

Every imported alert report is treated as **untrusted input**. This threat model evaluates
risks for the offline telemetry export design in [telemetry-design.md](telemetry-design.md).

## Foundational Principles

- **Allowlist-only projection:** Telemetry constructs a fresh dictionary containing only
  allowlisted fields and closed-enum/closed-rule values. It never uses regex redaction or
  recursive deletion of known sensitive keys.
- **Excluded source data:** Telemetry never copies `report_id`, source file paths,
  usernames, hostnames, IP addresses, process arguments, raw log lines, `message`,
  `description`, `recommendation`, `explanation`, hashes, or raw `evidence`.
- **Minimization is not anonymization:** Even with strict allowlisting, rule IDs, alert
  counts, severity/risk distributions, and `exported_at` timing can disclose operational
  context (for example, that SSH or file-integrity activity occurred on an endpoint).
- **Structural validation is not authenticity:** Canonical validation proves that an input
  report conforms to `schema-v1` or `legacy-unversioned` structure; it does **not** prove
  that the report is authentic, untampered, or represents truthful detection results.

## Threat & Mitigation Matrix

| Threat | Attack / Failure Vector | Mitigation in Telemetry Design |
| --- | --- | --- |
| Sensitive data in permitted string fields | Canary/PII placed in `rule_id`, `category`, `message`, or `evidence`. | `message`, `evidence`, `category`, `report_id`, etc. are never projected. `rule_id` is checked against a closed 17-rule allowlist; `severity` and `risk_level` are checked against a closed 5-value enum. |
| Unknown or malicious rule identifiers | Crafted `rule_id` (e.g., `CUSTOM-SECRET-USER` or injection payload). | Fail-closed `unsupported-rule` rejection for any `rule_id` not in the closed v1 allowlist. |
| Unexpected nested objects & extra fields | Extra keys on report, alert, telemetry root, or group objects. | Exact key-set equality checks reject any unknown or extra fields fail-closed. |
| Duplicate JSON keys | Ambiguous JSON objects overriding keys across parsers. | Delegated to canonical `parse_report_json()` (`_unique_object` hook), rejecting duplicate keys at every depth. |
| Nonfinite numbers, invalid Unicode, deep nesting | `NaN`/`Infinity`, lone surrogates, or deeply nested JSON crashing parser. | `parse_report_json()` rejects nonfinite constants, float overflow, and invalid UTF-8; Python recursion errors map to `incompatible`. |
| Oversized input or output | Multi-hundred-MiB input or bloated output exhausting memory/ingestion quotas. | Input capped at `2 MiB` (`2,097,152` bytes) before full parse; serialized output capped at `64 KiB` (`65,536` bytes). |
| Excessive alert counts & cardinality | Millions of alerts or combinatorial group explosion. | Input capped at `1,000` alerts; output capped at `128` unique `(rule_id, severity, risk_level)` groups. |
| Report tampering & authenticity limits | Locally modified or forged JSON report matching schema v1. | Explicitly documented residual risk: no cryptographic signing in v1; future ingestion requires operator review and synthetic-first gates. |
| Symlinks, special files, unsafe paths, & races | Reading `/dev/zero`, FIFOs, or symlinked targets; TOCTOU between `stat` and `open`. | Input opens with `O_RDONLY \| O_NONBLOCK \| O_NOFOLLOW` (preventing FIFO hangs) + `os.fstat()` verifying `S_ISREG` and size, failing closed if primitives are unsupported. Output uses trusted private dir, `0o600`, no-clobber (`O_EXCL` or private temp + `fsync` + no-clobber publish). Inode comparison alone does not eliminate all races; parent-dir symlinks remain a residual risk. |
| Existing-file overwrite & partial output | Clobbering existing telemetry or leaving truncated JSON on disk error. | No-clobber creation refuses overwrite; write errors unlink temporary/partial output; crash-related residual risks documented. |
| Exception messages exposing sensitive input | Parser/validation error echoing raw `evidence` keys or PII strings in tracebacks. | `raise TelemetryError(...) from None` suppresses parser chains; sanitized diagnostics never print raw input, paths, or locals. Does not protect against privileged debugging or process-memory inspection. |
| Repeated exports, replay, & duplicate ingestion | Re-exporting generates new `export_id`s; re-uploading replays an ID; conflicting payloads share an ID. | Saved telemetry parser (`parse_telemetry_json`) preserves `export_id`; Azure prefers one record per export envelope with structured `groups`; KQL deduplicates by `export_id` before expanding `groups`; conflicting payloads with the same `export_id` are not silently treated as identical. |
| Dependency or accidental network activity | New third-party packages or unintended HTTP calls during offline export. | Zero new runtime dependencies; offline export performs no network or credential operations. Regression tests monkeypatch socket/HTTP hooks (distinguished from mathematical impossibility proof). |
