# DAIR Containment Loop

**Isolate the host and revoke the identity at the same time — not one after the other.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](NOTICE)

An open reference implementation of the **Containment Loop** from the Dynamic Incident Response (DAIR) framework, targeting **Microsoft Defender for Endpoint** and **Microsoft Entra ID**.

Maintained by [IROC Security](https://github.com/irocsecurity).

---

## Why this exists

Most containment tooling — and most runbooks — do this:

```
isolate the host  →  wait for it to complete  →  revoke the user's sessions
```

In a credential-theft incident that ordering is actively harmful. The adversary's session is **independent of the endpoint**. Every second spent waiting on a device action is a second the stolen token remains usable from anywhere else on the internet.

DAIR models containment as a loop that runs **concurrently with scoping and with itself**. This tool implements the endpoint and identity halves as parallel operations:

```
                    ┌─────────────────────────┐
   incident ───────▶│   CONTAINMENT LOOP      │
                    ├───────────┬─────────────┤
                    │  MDE      │   Entra ID  │
                    │  isolate  │   revoke    │   ◀── simultaneous
                    │  device   │   sessions  │
                    └───────────┴─────────────┘
                                │
                         audit + report
```

Typical measured difference against a live tenant: **containment completes in roughly the time of the slower half, not the sum of both.** The tool reports both numbers on every run so you can see it.

```
[OK] mde.isolate -> WS-4417 (842 ms)
[OK] entra.revoke -> alice@example.org (611 ms)

Wall clock : 867 ms (concurrent)
Sequential : 1453 ms (what legacy ordering would have cost)
Saved      : 586 ms of adversary dwell time
```

---

## Quickstart

```bash
git clone https://github.com/irocsecurity/dair-containment-loop.git
cd dair-containment-loop
pip install -r requirements.txt

cp .env.example .env                                  # add your app credentials
cp config/containment.example.json config/containment.json   # add break-glass accounts

# Verify credentials and API reachability
python -m dair_containment preflight

# Dry run — the default. Nothing is changed.
python -m dair_containment contain \
    --host WS-4417 \
    --user alice@example.org \
    --config config/containment.json

# Act
python -m dair_containment contain \
    --host WS-4417 \
    --user alice@example.org \
    --config config/containment.json \
    --execute

# Undo
python -m dair_containment release \
    --host WS-4417 \
    --user alice@example.org \
    --config config/containment.json \
    --enable-account --execute
```

---

## Safety model

This tool cuts devices off the network and disables accounts. It is built to fail closed.

| Control | Behavior |
|---|---|
| **Dry-run by default** | Nothing acts without `--execute`. Dry runs still resolve targets and write audit records. |
| **Break-glass guardrail** | Refuses to run if `protected_users` is empty **or still contains template values**. An unpopulated guardrail looks like protection while providing none. |
| **Confirmation prompt** | `--execute` requires typing `YES` unless `--yes` is passed. |
| **Local checks first** | Guardrail validation runs before any network I/O, so it cannot be skipped by an auth failure. |
| **Append-only audit** | Every action — including dry runs and failures — writes a JSONL record with operator, target, mode, result, and the exact undo command. |
| **Reversibility is implemented** | `release` exists and is tested. An "undo" that only appears in documentation is not an undo. |

Exit codes: `0` success · `1` action failed · `2` auth/credential problem · `3` guardrail refusal · `64` bad invocation · `130` operator aborted.

---

## Required permissions

Create a dedicated app registration. **Certificate credentials strongly preferred** over client secrets — see [SECURITY.md](SECURITY.md).

| API | Permission | Type | Used for |
|---|---|---|---|
| WindowsDefenderATP | `Machine.Read.All` | Application | Resolve hostname → machine id; poll action status |
| WindowsDefenderATP | `Machine.Isolate` | Application | Isolate and release devices |
| Microsoft Graph | `User.Read.All` | Application | Resolve principal, read containment-relevant attributes |
| Microsoft Graph | `User.ReadWrite.All` | Application | `revokeSignInSessions`, toggle `accountEnabled` |

All require tenant admin consent. Scope the principal to exactly these four — it needs nothing else.

---

## Token mechanics you need to understand

`revokeSignInSessions` invalidates refresh tokens, session cookies, and Primary Refresh Tokens. It does **not** immediately invalidate already-issued *access* tokens.

| Condition | Adversary's residual access |
|---|---|
| CAE enabled + CAE-capable resource (Exchange, SharePoint, Teams, Graph) | ~2 minutes |
| No CAE, or non-CAE-capable resource | Up to the full access token lifetime — **60–90 minutes** |
| Adversary holds an app refresh token from an illicit OAuth consent grant | **Indefinite** until that grant is revoked |

**A password reset alone is never containment.** This tool implements the identity half of the loop; revoking illicit OAuth grants belongs to the eradication loop and is deliberately out of scope here.

### Guest / B2B principals

A guest's credential, MFA methods, and session live in the **home tenant**. Revoking their sessions in your tenant invalidates only your resource-tenant tokens — the adversary completes SSO and is re-issued new ones within seconds.

The tool detects guests, warns, and when `--disable-account` is passed **disables the guest object before revoking**, because that ordering is what actually contains. It cannot remediate the credential; notify the home tenant.

### Hybrid-synced principals

A cloud-side `accountEnabled=false` is overwritten by the next directory sync. The tool warns when it sees `onPremisesSyncEnabled`. Disable in on-premises AD and force a delta sync.

---

## DAIR mapping

| DAIR concept | Implementation |
|---|---|
| Concurrent Response Action loops | `ThreadPoolExecutor` fires both halves; neither blocks the other |
| Decision velocity | Both actions are reversible, so they are suitable for pre-delegated execution without an approval round-trip |
| Reversibility test | `release` implements the undo; every audit record carries the exact undo command |
| Post-review oversight | Append-only JSONL audit replaces pre-approval as the control |
| Loops feed each other | `--json` output is designed to be consumed by a scoping pipeline |

> Derived from Dynamic Incident Response by Joshua Wright, used under CC BY 4.0.

---

## Testing

Offline — no tenant or network required:

```bash
python tests/test_loop.py          # or: python -m pytest -q
```

13 tests cover guardrail fail-closed behavior, dry-run safety, guest disable-before-revoke ordering, audit completeness, and a **concurrency regression test** that fails if the loop ever becomes sequential.

---

## Scope and non-goals

**In scope:** concurrent MDE device isolation and Entra ID session revocation, with guardrails, audit, and a working undo.

**Not in scope:** scoping queries, OAuth grant revocation, mailbox rule eradication, forensic collection, recovery workflows. Those are separate loops. This tool does one thing so it can be reviewed in an afternoon and trusted in an incident.

---

## More from IROC Security

This tool is the free, open piece of a larger body of work on applying DAIR to cloud environments.

| | |
|---|---|
| **Free — this repo** | The containment loop tool, Apache-2.0. Use it, fork it, ship it. |
| **Free download** | *Cloud Identity Compromise: Containment Quick Reference* — the token mechanics above as a one-page field card. |
| **Newsletter** | The full **Entra ID Account Compromise Runbook** — scoping query pack, persistence artifact inventory, eradication verification gates, and exposure-determination workflow. |
| **Paid** | Full DAIR runbook library, facilitated tabletop exercises, and authority-matrix implementation for pre-delegated containment. |

Links: `[ADD-SITE-LINKS]`

---

## Contributing

Issues and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Particularly interested in: additional EDR/IdP backends, SOAR integration patterns, and real-world latency measurements from live tenants.

Contributions are accepted under the [Developer Certificate of Origin](DCO) 1.1 — sign off your commits with `git commit -s`. There is no CLA, nothing to sign, and no copyright assignment: you keep ownership of your work.

## Security

Do not open a public issue for a vulnerability in this tool. See [SECURITY.md](SECURITY.md).

## License and reuse

**Code:** [Apache License 2.0](LICENSE). Use it, fork it, run it commercially, build a product on it. What the license asks in return is that you keep the copyright and license notices intact and state what you changed — attribution is a condition of use, not a courtesy.

**Documentation and framework-derived prose:** additionally available under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See [NOTICE](NOTICE).

**Names and marks:** *not* licensed. The Apache License grants rights to the code, not to "IROC Security" or to this project's name — see [TRADEMARK.md](TRADEMARK.md). Fork freely and ship what you build; give your version its own name so a practitioner can tell whose code is about to isolate their production hosts.

> Derived from Dynamic Incident Response by Joshua Wright, used under CC BY 4.0.
