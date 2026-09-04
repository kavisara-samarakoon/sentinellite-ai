# Security Policy

SentinelLite AI is an on-demand, local, defensive observation and report-review project
for authorized learning, development, and evaluation. It is not a production EDR and does
not promise enterprise monitoring, response, or support.

## Supported Release Status

Published versions are pre-release software. Security fixes are evaluated for the current
development branch and most recent GitHub pre-release; older alpha milestones are retained
as historical records and should not be assumed to receive fixes.

## Defensive Scope

The project may perform the following only when an authorized user explicitly runs a
command:

- parse an explicitly selected local authentication log
- observe current process metadata
- observe active network connection metadata exposed by the operating system
- read metadata and hashes for explicitly selected file paths
- create and compare an explicitly requested file integrity baseline
- apply transparent local detection and risk-scoring rules
- write and review local JSON alert reports
- export a separate privacy-minimized notification summary to a local file
- display deterministic investigation guidance derived from local templates

The explanation templates are deterministic and rule-based. They are not real AI or LLM
execution and do not call a model, external API, or remote explanation service.

## Prohibited Scope

SentinelLite AI must not include or claim:

- malware, credential theft, phishing, backdoors, ransomware, persistence, or evasion
- exploitation, unauthorized access, probing, offensive tooling, or harmful payloads
- active network scanning, port scanning, packet sending, connection creation, or DNS probing
- email, Slack, Discord, webhook, SMS, provider, token, or external notification delivery
- application network traffic or external API calls
- real AI or LLM execution
- a daemon, background service, scheduler, persistent watcher, or automatic monitoring loop
- automatic remediation, process termination, IP blocking, firewall changes, or account changes
- file deletion, repair, quarantine, or modification of observed files
- a production EDR, comprehensive threat detection, or proof of compromise

Alerts, scores, and explanations identify observations for human investigation. They do not
establish that malware, compromise, or unauthorized activity occurred. A zero-alert result
is not a security guarantee.

## Authentication Logs and Authorization

Authentication scanning requires an exact path supplied by the user. Candidate inventory
does not read log contents or start a scan. SentinelLite AI does not invoke `sudo`, elevate
privileges, or change permissions or ownership.

Do not commit or distribute real authentication logs. The documented demo and release
validation use bundled non-sensitive fixtures rather than real host logs.

## Secrets and Sensitive Data

Do not commit:

- API keys, passwords, tokens, private keys, or `.env` files
- real user or authentication logs
- personal data or VM credentials
- generated alert reports, notification summaries, or file integrity baselines
- host-specific process, network, file, or security evidence

Alert reports can contain detailed operational evidence. Notification summaries omit alert
messages, evidence, explanation text, and common sensitive detail fields, but still expose
report timing, matched rule IDs, categories, severity, and risk information. Treat both
artifact types as sensitive.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting for this repository when it is available. Include
the affected version or commit, the smallest safe reproduction, expected and observed
behavior, and the potential impact.

If private reporting is unavailable, open a minimal public issue asking the maintainer for
a private reporting channel. Do not publish credentials, personal data, real host logs,
weaponized exploit instructions, or sensitive report contents in a public issue.

This project does not promise enterprise response times or continuous security support.
