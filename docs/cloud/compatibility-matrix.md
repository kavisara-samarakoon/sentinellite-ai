# SentinelLite AI — Environment Compatibility Matrix

This matrix records the verification status and scope boundaries for SentinelLite AI
`v1.3.0-beta` (`1.3.0b0`) across development, CI, local VM, and planned cloud VM targets.

## Matrix

| Environment | Architecture | Python | Status | Evidence Scope & Boundaries |
| --- | --- | --- | --- | --- |
| macOS development host | ARM64 (`arm64`) | `3.14.6` | **Verified** | Full suite (1,991 tests), Ruff, `pip check`, wheel/sdist build, isolated wheel install, synthetic `demo`/`scan-auth`/dashboard smoke, and manual Safari review of static HTML. `doctor` emits expected non-Linux warning. Does **not** establish Linux or Azure compatibility. |
| GitHub Actions CI (`ubuntu-latest`) | x86-64 (`x86_64`) | `3.11`, `3.14` | **Verified (CI only)** | Automated test suite, Ruff, `pip check`, wheel build, isolated install, and fixture smoke checks. Does **not** establish Azure runtime, cloud VM permissions, or ARM64 compatibility. |
| ARM-SecNet UTM Ubuntu VM | ARM64 (`aarch64`) | `>=3.11` | **Deferred ([Issue #17](https://github.com/kavisara-samarakoon/sentinellite-ai/issues/17))** | Exact `v1.3.0-beta` wheel validation was deferred because the UTM VM was unavailable on 2026-11-27. Prior Lab 03 evidence (`d1775f0`) does **not** validate `v1.3.0-beta` or prove universal ARM64 compatibility. |
| Planned Azure Ubuntu LTS VM | x86-64 (`x86_64`) | `>=3.11` | **Planned (Pending)** | Target workload for SENT-C1 on ARM-SecNet-managed Azure infrastructure using the published `v1.3.0-beta` wheel and [VM Validation Procedure](vm-validation.md). |
| Optional future Azure Ubuntu VM | ARM64 (`aarch64`) | `>=3.11` | **Optional / Untested** | Subject to ARM-SecNet image availability and owner approval; not yet provisioned or tested. |
| Other Linux distributions (RHEL, Fedora, Debian, Alpine, etc.) | Any | `>=3.11` | **Untested** | Bundled `sample_rhel_secure.log` tests log-line parsing only; it does **not** establish RHEL/Fedora runtime compatibility. |

## Packaging & Dependency Distinctions

- **Application wheel (`sentinellite_ai-1.3.0b0-py3-none-any.whl`):** Pure Python (`py3-none-any`),
  platform-independent.
- **Runtime dependencies:**
  - `psutil`: Platform-specific compiled C extension wheel (or source build requiring Python
    development headers and a C compiler if a matching binary wheel is unavailable).
  - `PyYAML`: May install a platform-specific binary wheel (`libyaml`) or pure-Python fallback.
  - `rich`, `typer`: Pure Python wheels.
- **Ubuntu venv prerequisite:** Minimal Ubuntu installations may omit `ensurepip` and require
  `sudo apt install python3-venv` before creating isolated virtual environments.
