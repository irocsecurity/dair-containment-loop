# Contributing

Contributions are genuinely welcome. This is a tool that gets better with
real-world exposure, and most of what would improve it — additional backends,
latency data from live tenants, edge cases we have not hit — can only come from
people running it somewhere we are not.

## Ground rules

1. **Safety defaults are not negotiable.** Any change that makes the tool act
   without `--execute`, weakens the break-glass guardrail, or removes an audit
   record will be declined. Additions that make it *safer* are welcome.
2. **Reversibility is a feature.** If you add a containment action, you add its
   undo and a test for both.
3. **Tests must run offline.** No contributor should need a tenant to validate a
   change. Use the fakes in `tests/test_loop.py` as the pattern.
4. **The concurrency test must keep passing.** If the loop becomes sequential,
   the tool has lost its reason to exist.
5. **Local safety checks stay ahead of network calls.** Guardrail validation runs
   before authentication is constructed, deliberately — a guardrail that is only
   evaluated once the network is reachable is not a guardrail.

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin](DCO) (DCO 1.1) rather
than a Contributor License Agreement. There is no document to sign and no
copyright to assign — you keep ownership of your contribution, and it is
licensed to the project under Apache-2.0 along with everything else.

What the DCO asks is that you certify you have the right to contribute what you
are contributing. You do that by signing off each commit:

```bash
git commit -s -m "your message"
```

which appends a line to the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and an email address you can be reached at. If you forgot on
your last commit, `git commit --amend -s` fixes it; for a branch,
`git rebase --signoff main`.

**Contributing on behalf of an employer?** Make sure you actually have the right
to. Many employment agreements assign IP in work-related code to the employer.
If this code touches your day job, get it cleared before you open the PR — that
is far easier than unwinding it afterward.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python tests/test_loop.py
```

## Pull requests

- One logical change per PR.
- Sign off every commit (`-s`).
- Update the README permission table if you add an API call, and call out any
  new required permission explicitly — reviewers will check that the service
  principal stays least-privilege.
- Run the test suite and paste the output.
- If you are changing behavior during an incident, say in the PR what a
  responder would see differently at 2 a.m.

## Good first contributions

- Additional EDR backends (CrowdStrike, SentinelOne) behind the same interface
- Okta or Google Workspace as identity backends
- Structured output adapters for SOAR platforms
- **Real-world latency measurements from live tenants.** The wall-clock versus
  sequential figures are the project's central claim, and more data from more
  environments makes it stronger — or corrects it, which is equally useful.

## Naming and trademarks

Fork freely. If you ship a modified version, give it your own name — see
[TRADEMARK.md](TRADEMARK.md). You may say it is derived from this project;
please do not call it the DAIR Containment Loop, so practitioners can tell whose
code they are running against their production tenant.

## Attribution

The DAIR framework is by Joshua Wright, licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Contributions that
extend the framework-derived documentation must preserve the attribution notice
in [NOTICE](NOTICE).
