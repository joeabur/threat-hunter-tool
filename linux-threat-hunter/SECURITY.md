# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** using GitHub's "Report a vulnerability" (private security advisory) feature on this repository. Do not open a public issue. Include the affected version, steps to reproduce and impact. We aim to acknowledge reports promptly and will credit reporters who wish to be named.

## In scope

- Code execution, command injection or privilege escalation through evidence files, logs, rules, IOC files or configuration.
- Path traversal or symlink issues when reading evidence or writing reports/baselines.
- Redaction failures that leak secrets into reports.
- Catastrophic regex or resource-exhaustion problems that bypass the documented limits.

## Out of scope

- Detections that are missed or noisy (open a normal issue; this is a hunting aid with documented gaps).
- Findings about the monitored host itself.

## Safe use

Run only on systems you are authorized to examine. Evidence directories, baselines and reports can contain sensitive command lines, usernames and log content: store them with restricted permissions and do not upload them to third-party services. See [docs/security-and-limitations.md](docs/security-and-limitations.md).
