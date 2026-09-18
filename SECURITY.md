# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability in this tool.

Email `contactus@irocsecurity.com` with a description, reproduction steps, and impact
assessment. Expect an acknowledgement within 3 business days and a substantive
response within 10.

We support coordinated disclosure and will credit reporters who want it.

## Threat model for operators

This tool holds credentials that can **cut devices off the network** and
**disable user accounts**. Treat the principal and the host that runs it as
tier-0 infrastructure.

### Credential handling

| Do | Don't |
|---|---|
| Use certificate credentials (`DAIR_CERT_PATH` + `DAIR_CERT_THUMBPRINT`) | Use a long-lived client secret |
| Store the certificate in a secrets manager or HSM-backed store | Commit `.env`, `*.pem`, or `*.pfx` |
| Scope the app registration to exactly the four permissions in the README | Grant `Directory.ReadWrite.All` "to be safe" |
| Rotate on a defined schedule and on any operator departure | Share the principal across unrelated automation |
| Run from a managed, monitored host | Run from a laptop with the secret in shell history |

`.gitignore` already excludes `.env`, `*.pem`, `*.pfx`, `*.key`, the audit log,
and the populated config. Verify before your first commit.

### Blast radius

A compromise of this principal gives an attacker the ability to isolate
arbitrary devices and disable arbitrary accounts — a denial-of-service against
your own organization, and a way to disrupt a response in progress.

Mitigations:

* Keep `protected_users` populated with every break-glass account. The tool
  refuses to run when it is empty or still contains template values.
* Ship the JSONL audit log to your SIEM and alert on execution outside expected
  windows or by unexpected operators.
* Prefer `--isolation-type selective` where full isolation is not justified.
* Consider a Conditional Access policy restricting the principal to known IPs.

### What this tool deliberately does not do

* It does not revoke OAuth consent grants. Session revocation does **not**
  remove app-plane persistence; that belongs to the eradication loop.
* It does not reset passwords. A reset alone is not containment.
* It does not touch on-premises Active Directory. Hybrid-synced accounts need
  an on-premises action, and the tool warns when it detects one.

### Logging and secrets

Token material is never logged. MSAL error payloads are surfaced with error
code, description, and correlation id only. `msal` and `urllib3` loggers are
pinned to WARNING so that `--verbose` does not echo request metadata.
