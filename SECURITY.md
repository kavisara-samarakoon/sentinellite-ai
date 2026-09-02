# Security Policy

SentinelLite AI is a defensive cybersecurity project focused on monitoring, alerting, reporting, and security learning.

## Allowed Scope

This project may include:

- Linux log monitoring
- process monitoring
- network visibility
- file integrity monitoring
- rule-based detection
- risk scoring
- JSON reporting
- local, privacy-minimized notification summary export
- AI-assisted defensive explanation

## Not Allowed Scope

This project must not include:

- malware
- credential theft
- phishing kits
- backdoors
- ransomware behavior
- stealth or evasion tooling
- unauthorized exploitation
- destructive scripts
- harmful payloads

## Secrets Policy

Do not commit:

- API keys
- passwords
- private keys
- `.env` files
- real user logs
- personal data
- VM credentials

## Generated Security Artifacts

Generated SentinelLite alert reports and notification summaries may contain or imply operational security metadata. Notification summaries omit alert messages, evidence, explanation text, and common sensitive detail fields, but they still identify report timing, rule matches, categories, severity, and risk information. Treat both artifact types as sensitive.

- Do not commit generated reports or notification summaries.
- Do not share these artifacts casually.
- Store them outside public repositories unless they intentionally contain only fake demonstration data.
- SentinelLite AI v0.8 exports notification summaries locally and does not send them externally.
- Any future external delivery integration should require explicit opt-in and appropriate secret handling.

## Version 1 Safety Rule

Version 1 should monitor, alert, report, explain, and recommend.

It should not automatically kill processes, delete files, block IP addresses, or modify firewall rules.
