# Contributing

Thanks for considering a contribution.

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

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python tests/test_loop.py
```

## Pull requests

* One logical change per PR.
* Update the README permission table if you add an API call.
* Note any new required permission explicitly — reviewers will check that the
  principal stays least-privilege.
* Run the test suite and paste the output.

## Good first contributions

* Additional EDR backends (CrowdStrike, SentinelOne) behind the same interface
* Okta / Google Workspace as identity backends
* Structured output adapters for SOAR platforms
* Real-world latency measurements from live tenants — the wall-clock vs.
  sequential numbers are the tool's central claim and more data makes it stronger

## Attribution

The DAIR framework is by Joshua Wright, CC BY 4.0. Contributions that extend the
framework-derived documentation must preserve the attribution notice.
