# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting ("Security" tab, "Report a vulnerability") for this repository. Include the version,
steps to reproduce, impact, and a minimal synthetic reproducer. Do not include real host data.

We aim to acknowledge reports promptly and to fix confirmed issues in the next release; this is
a best-effort, volunteer-maintained project with no guaranteed response time.

## In scope

Path traversal or symlink escapes in evidence handling, regex denial of service, command
injection via collected data, redaction bypasses that leak secrets, CSV/Markdown injection in
reports, and unsafe handling of untrusted evidence or rule files.

## Out of scope

Findings that the tool does not detect a given malware family (see
[docs/security-and-limitations.md](docs/security-and-limitations.md)), and issues requiring a
prior compromise of the analyst's machine.

## Handling evidence

Evidence and reports can contain sensitive data. Treat them as confidential and review
redaction before sharing anything.
