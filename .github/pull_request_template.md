## What this changes

<!-- One paragraph. What is different after this merges? -->

## Why

<!-- What problem does it solve? Link an issue if one exists. -->

## During an incident, what would a responder see differently?

<!-- If this changes runtime behavior, answer concretely. If it is docs or
     tooling only, write "no runtime change". -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) — see [DCO](../DCO)
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `python tests/test_loop.py` passes
- [ ] Safety defaults unchanged: dry-run is still the default, the guardrail
      still fails closed, every action still writes an audit record
- [ ] If a containment action was added, its undo and tests for both exist
- [ ] If an API call was added, the README permission table is updated and any
      new permission is called out explicitly below

## New permissions requested

<!-- "none", or name each one and why the tool cannot work without it. -->
