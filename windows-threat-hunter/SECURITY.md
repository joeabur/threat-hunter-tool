# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability"). If that is not available, contact the repository owner through their GitHub profile and ask for a private channel before sharing details.

Helpful details: affected version, what you did, what you expected, what happened, and a minimal synthetic reproduction. Never include real credentials, real host names, or real incident data.

You can expect an acknowledgement, a fix or a documented decision, and credit if you want it. This is a volunteer project, so there is no guaranteed response time.

## What counts as a vulnerability here

This tool is read-only by design. These are in scope:

- Anything that makes the tool change the inspected system (write, delete, stop, disable, or execute something it discovered).
- Anything that sends data off the machine.
- A way for a crafted snapshot, rule file, configuration, suppression file, XDR export or event log record to run code, read files outside the intended inputs, or write outside the chosen output directory.
- Report injection: script or markup that runs when an HTML report is opened, or a formula that runs when a CSV is opened in a spreadsheet.
- Regular expression or parsing inputs that cause an unbounded hang.
- A leak of secrets or user names that the redaction setting claims to mask.

Detection gaps (a technique the rules do not catch) are normal feature requests, not vulnerabilities. See [docs/security-and-limitations.md](docs/security-and-limitations.md).

## Supported versions

Only the latest release is supported.
