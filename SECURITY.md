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

## Version 1 Safety Rule

Version 1 should monitor, alert, report, explain, and recommend.

It should not automatically kill processes, delete files, block IP addresses, or modify firewall rules.
