# Project rules for Claude

This tool isolates hosts and disables user accounts in production tenants. The
safety properties below are not style preferences — they are why it is safe to
run. Do not weaken them to make something else work.

## Invariants — never change these without an explicit instruction

1. **Dry-run is the default.** Nothing acts without `--execute`. Dry runs still
   resolve targets and still write audit records.
2. **The break-glass guardrail fails closed.** It refuses to run when
   `protected_users` is empty *or* still contains template values. An
   unpopulated guardrail looks like protection while providing none.
3. **Local safety checks run before any network I/O.** Guardrail validation
   happens before the auth client is constructed. A guardrail only evaluated
   once the network is reachable is not a guardrail.
4. **Every action writes an audit record**, including dry runs and failures,
   with operator, target, mode, result, and the exact undo command. Post-review
   auditing is what makes acting without pre-approval defensible.
5. **Every containment action has a working, tested undo.** An undo that exists
   only in documentation is not an undo.
6. **CI triggers on `pull_request`, never `pull_request_target`.**
   `pull_request_target` runs with repository secrets in scope against code
   from a fork. That is the mechanism behind real build-pipeline compromises.
   If the goal is "review fork PRs," the answer is not this. Leave it alone.
7. **The concurrency test must keep passing.** If the loop becomes sequential,
   the tool has lost its reason to exist.
8. **Minimal third-party Actions.** `ci.yml` uses only `actions/checkout` and
   `actions/setup-python`, both first-party; scanners install from PyPI. Every
   additional Action is another repository with access to the workflow. Prefer
   `gh` (preinstalled on runners) over wrapping a third-party action.

## Conventions

- Commits are signed off: `git commit -s` (DCO 1.1, no CLA).
- Author identity for this repo is `lemanuel.williams@irocsecurity.com`.
- Remote uses the `github-iroc` SSH alias, which routes to the IROC key in
  1Password. A plain `git@github.com:` remote authenticates as the personal
  account instead.
- Python targets 3.9+. `ruff check` and `ruff format --check` must pass;
  `Optional[X]` and `typing.Dict` are kept deliberately (UP006/UP007/UP045 are
  ignored) because of the 3.9 floor.
- Tests run offline with fakes. No contributor should need a tenant.
- Per-file headers: copyright line plus `SPDX-License-Identifier: Apache-2.0`.

## Before changing a workflow

`release.yml` never runs in CI — it fires only on a `v*.*.*` tag. A green check
on a PR that touches it proves nothing. Validate with a throwaway tag.

## Attribution

Derived from Dynamic Incident Response by Joshua Wright, used under CC BY 4.0.
Keep the attribution notice in NOTICE and in framework-derived documentation.
