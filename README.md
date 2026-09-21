# DAIR Containment Loop

**Isolate the host and revoke the identity at the same time — not one after the other.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](NOTICE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/irocsecurity/dair-containment-loop/badge)](https://scorecard.dev/viewer/?uri=github.com/irocsecurity/dair-containment-loop)

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

Because both halves run concurrently, **containment completes in roughly the time of the slower half rather than the sum of both.** The tool reports both numbers on every run so you can measure it in your own environment.

The concurrency property is covered by `tests/test_loop.py::TestConcurrency`, which fails if the loop ever silently becomes sequential. Output looks like this (timings illustrative):

```
[ACCEPTED] mde.isolate -> ws-4417.corp.example.org (842 ms)
         note: Defender has accepted the isolation; it is not in effect yet. Confirm with: dair-contain status --host ws-4417.corp.example.org --wait
[OK] entra.revoke -> alice@example.org (611 ms)

Wall clock : 867 ms (concurrent)
Sequential : 1453 ms (what legacy ordering would have cost)
Saved      : 586 ms of adversary dwell time
```

`[ACCEPTED]` is deliberate. Defender device actions are asynchronous: the API accepting a request is not the device being isolated. The tool reports `[OK]` only for actions that are done when the call returns, and `status` tells you when the rest have taken effect.

### Lab validation

Validated against a live Entra ID tenant with a Defender for Endpoint–onboarded Windows device, one device and a handful of test accounts. These are single-tenant observations, not benchmarks; your latency will differ.

| Observation | Measured |
|---|---|
| Isolation in effect after the API accepted it | 1–4 s |
| Release in effect after the API accepted it | **13 s to 13 min** (13 s, 374 s, 796 s across three runs) — unpredictable, so check with `status --wait` |
| Isolation and session revocation both in effect, run together | within ~5 s |
| Revoked user signed out of Outlook on the web (CAE) | ~26 s |
| Host isolation **alone**: user's cloud session after the device came back | **still signed in** — isolation does not contain the identity |
| Standard user disabled and re-enabled | works |
| Guest (B2B) user disabled, then re-enabled | access blocked, then restored |
| User holding an Entra admin role disabled | **refused (HTTP 403)** — see [Required permissions](#required-permissions) |

The fifth row is the reason this tool exists: cutting the device off the network did nothing to the session a thief would be using.

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

# Confirm it has taken effect, not just been accepted (read-only)
python -m dair_containment status --host WS-4417 --user alice@example.org --wait

# Undo
python -m dair_containment release \
    --host WS-4417 \
    --user alice@example.org \
    --config config/containment.json \
    --enable-account --execute
```

Guest UPNs contain `#`, so quote them: `--user 'bob_partner.com#EXT#@yourtenant.onmicrosoft.com'`.

### Checking status

`status` is read-only and needs no guardrail config. For a device it derives the current state from Defender's isolate/release history — `ISOLATED`, `NOT ISOLATED`, or `ISOLATION PENDING` / `RELEASE PENDING` while a request is still in flight — and `--wait` polls until it settles (default timeout 20 minutes, because releases have been measured at anything from 13 seconds to over 13 minutes). For a user it shows whether the account is enabled and the time from which sessions are valid; a time at or after containment confirms the revocation landed.

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
| WindowsDefenderATP | `Machine.Read.All` | Application | Resolve hostname → machine id; read isolation status |
| WindowsDefenderATP | `Machine.Isolate` | Application | Isolate and release devices |
| Microsoft Graph | `User.Read.All` | Application | Resolve principal, read containment-relevant attributes |
| Microsoft Graph | `User.RevokeSessions.All` | Application | `revokeSignInSessions` |
| Microsoft Graph | `User.EnableDisableAccount.All` | Application | Toggle `accountEnabled` — only needed for `--disable-account` / `--enable-account` |

All are Application permissions and require tenant admin consent. The principal needs nothing else. `preflight` reads the roles actually granted in each token and fails if one is missing.

`User.ReadWrite.All` also satisfies the three Graph rows and is still accepted, but it lets the app rewrite any attribute of any user. Prefer the narrow set.

**Accounts that hold an Entra admin role cannot be disabled with these permissions**, and that is by design. Graph refuses (HTTP 403) unless the app itself is assigned an admin role such as Privileged Authentication Administrator — which would let anyone holding its certificate reset Global Administrators. This tool does not ask for that, and you should think hard before granting it. Session revocation still works on admin accounts; disable them through your privileged-access process. In the output, revoke and disable are reported separately, so a refused disable never hides a revocation that succeeded.

---

## Token mechanics you need to understand

`revokeSignInSessions` invalidates refresh tokens, session cookies, and Primary Refresh Tokens. It does **not** immediately invalidate already-issued *access* tokens.

| Condition | Adversary's residual access |
|---|---|
| CAE enabled + CAE-capable resource (Exchange, SharePoint, Teams, Graph) | Near real time, up to ~15 minutes for event propagation (~26 s observed in lab) |
| No CAE, or non-CAE-capable resource | Up to the full access token lifetime — **60–90 minutes** |
| Adversary holds an app refresh token from an illicit OAuth consent grant | **Indefinite** until that grant is revoked |

**A password reset alone is never containment.** This tool implements the identity half of the loop; revoking illicit OAuth grants belongs to the eradication loop and is deliberately out of scope here.

### Guest / B2B principals

A guest's credential, MFA methods, and session live in their **home organization**. Revoking their sessions in your tenant invalidates only your tenant's tokens; the guest can sign in again through their home organization, which your tenant cannot reach.

So for guests, `--disable-account` is what contains. The tool warns when a guest is targeted without it, and when it is passed **disables the guest object before revoking**, so there is no window in which a revoked guest can sign straight back in. In lab validation, disabling the guest blocked its access to the tenant, and re-enabling restored it. The tool cannot remediate the credential itself; notify the guest's home organization.

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

98 tests cover guardrail fail-closed behavior and ordering, target resolution (exact device names, guest UPN encoding), dry-run and failure reporting, accepted-versus-in-effect state, guest disable-before-revoke ordering, least-privilege preflight, audit completeness, and a **concurrency regression test** that fails if the loop ever becomes sequential. Every defect found in lab validation has a test named for it.

---

## Scope and non-goals

**In scope:** concurrent MDE device isolation and Entra ID session revocation, with guardrails, audit, and a working undo.

**Not in scope:** scoping queries, OAuth grant revocation, mailbox rule eradication, forensic collection, recovery workflows. Those are separate loops. This tool does one thing so it can be reviewed in an afternoon and trusted in an incident.

---

## How this differs from what already exists

Most of what this tool does can be done other ways. It is worth knowing which one you actually want.

**[Automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)** in Microsoft Defender XDR contains devices and disables accounts natively, with no tooling at all. It acts on Microsoft's detections, on Microsoft's timing, and is gated behind Defender XDR licensing. Where it covers your scenario and you are licensed for it, use it — it reacts faster than any human can.

**SOAR playbooks and Logic Apps** — Sentinel, XSOAR, Splunk SOAR, and the various public MDE isolation playbooks — make the same API calls. They need a platform, a subscription, or a Function App to run inside, and their steps execute in sequence.

**This tool** is for the case those two leave open: a responder who has decided to contain, on their own judgment, right now — with no SOAR platform, no cloud infrastructure, and nothing to review but a single Python package.

What it adds on top of the two API calls:

- Both halves run concurrently, and a test fails if that ever silently regresses
- Dry run is the default; `--execute` has to be asked for
- Guardrails fail closed — an empty or template-valued protected list refuses to run rather than proceeding unprotected
- Every action writes an audit record, and every containment action has a working undo
- Guest and B2B principals are disabled *before* revocation, because revoking sessions alone does not contain a credential that lives in another tenant

---

## More from IROC Security

This repository is part of IROC Security's ongoing work applying Dynamic Incident
Response concepts to cloud identity and modern security operations. Additional
runbooks, tabletop exercises, implementation guidance, and research will be
released as the library develops.

Follow [IROC Security](https://irocsecurity.com) for future releases.

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
