"""Offline tests for the containment loop. No network, no tenant required.

Run with:  python -m pytest -q     (or)     python tests/test_loop.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dair_containment.audit import AuditLog  # noqa: E402
from dair_containment.loop import (  # noqa: E402
    ContainmentLoop,
    GuardrailNotConfigured,
    LoopResult,
    ActionResult,
)


class FakeDefender:
    """Stands in for DefenderClient with a deliberate 200 ms latency."""

    def __init__(self):
        self.isolated = []
        self.released = []

    def resolve_machine(self, identifier):
        time.sleep(0.2)
        return {
            "id": "a" * 40,
            "computerDnsName": identifier,
            "osPlatform": "Windows11",
            "healthStatus": "Active",
            "lastSeen": "2026-09-18T04:00:00Z",
        }

    def active_isolation(self, machine_id):
        return None

    def isolate(self, machine_id, comment, isolation_type):
        self.isolated.append((machine_id, isolation_type))
        return {"id": "action-1", "status": "Pending"}

    def release(self, machine_id, comment):
        self.released.append(machine_id)
        return {"id": "action-2", "status": "Pending"}


class FakeEntra:
    """Stands in for EntraClient with a deliberate 200 ms latency."""

    def __init__(self, user_type="Member"):
        self.revoked = []
        self.enabled_changes = []
        self._user_type = user_type

    def resolve_user(self, identifier):
        time.sleep(0.2)
        return {
            "id": "11111111-2222-3333-4444-555555555555",
            "userPrincipalName": identifier,
            "accountEnabled": True,
            "userType": self._user_type,
            "onPremisesSyncEnabled": False,
            "signInSessionsValidFromDateTime": "2026-09-01T00:00:00Z",
        }

    def revoke_sessions(self, user_id):
        self.revoked.append(user_id)
        return True

    def set_account_enabled(self, user_id, enabled):
        self.enabled_changes.append((user_id, enabled))

    def sessions_valid_from(self, user_id):
        return "2026-09-18T04:05:00Z"


def _loop(mde=None, entra=None, audit_path=None, **kwargs):
    return ContainmentLoop(
        defender=mde or FakeDefender(),
        entra=entra or FakeEntra(),
        audit=AuditLog(audit_path or os.path.join(tempfile.mkdtemp(), "audit.jsonl")),
        protected_users=kwargs.pop("protected_users", ["bg-admin@realtenant.onmicrosoft.com"]),
        protected_devices=kwargs.pop("protected_devices", ["DC01"]),
        **kwargs,
    )


class TestGuardrail(unittest.TestCase):
    def test_empty_protected_users_refuses(self):
        with self.assertRaises(GuardrailNotConfigured):
            _loop(protected_users=[])

    def test_template_values_refuse(self):
        with self.assertRaises(GuardrailNotConfigured):
            _loop(protected_users=["bg-admin-01@CHANGE-ME.onmicrosoft.com"])

    def test_contoso_placeholder_refuses(self):
        with self.assertRaises(GuardrailNotConfigured):
            _loop(protected_users=["bg@contoso.onmicrosoft.com"])

    def test_no_guardrail_override_allows_empty(self):
        loop = _loop(protected_users=[], require_guardrail=False)
        self.assertIsNotNone(loop)

    def test_protected_user_is_refused(self):
        entra = FakeEntra()
        loop = _loop(entra=entra, protected_users=["bg-admin@realtenant.onmicrosoft.com"])
        result = loop.contain(host=None, user="bg-admin@realtenant.onmicrosoft.com",
                              comment="test", execute=True)
        self.assertFalse(result.ok)
        self.assertIn("protected-principal list", result.results[0].error)
        self.assertEqual(entra.revoked, [], "protected principal must not be revoked")

    def test_protected_device_is_refused(self):
        mde = FakeDefender()
        loop = _loop(mde=mde, protected_devices=["DC01"])
        result = loop.contain(host="DC01", user=None, comment="test", execute=True)
        self.assertFalse(result.ok)
        self.assertEqual(mde.isolated, [], "protected device must not be isolated")


class TestDryRun(unittest.TestCase):
    def test_dry_run_performs_no_mutations(self):
        mde, entra = FakeDefender(), FakeEntra()
        loop = _loop(mde=mde, entra=entra)
        result = loop.contain(host="WS-1234", user="alice@example.org",
                              comment="test", execute=False)
        self.assertTrue(result.ok)
        self.assertEqual(result.mode, "dry-run")
        self.assertEqual(mde.isolated, [])
        self.assertEqual(entra.revoked, [])


class TestConcurrency(unittest.TestCase):
    def test_halves_run_in_parallel(self):
        """Wall clock must be materially less than the sum of both halves.

        This is the property the whole tool exists to provide -- if it regresses,
        the loop has silently become sequential.
        """
        loop = _loop()
        result = loop.contain(host="WS-1234", user="alice@example.org",
                              comment="test", execute=True)
        self.assertTrue(result.ok, msg=result.report())
        self.assertLess(
            result.wall_clock_ms, result.serial_ms * 0.75,
            msg=f"Loop appears sequential: wall={result.wall_clock_ms}ms serial={result.serial_ms}ms",
        )

    def test_both_actions_executed(self):
        mde, entra = FakeDefender(), FakeEntra()
        loop = _loop(mde=mde, entra=entra)
        loop.contain(host="WS-1234", user="alice@example.org", comment="test", execute=True)
        self.assertEqual(len(mde.isolated), 1)
        self.assertEqual(len(entra.revoked), 1)


class TestGuestOrdering(unittest.TestCase):
    def test_guest_is_disabled_before_revoke(self):
        """Guests must be disabled first; revocation alone is not containment."""
        entra = FakeEntra(user_type="Guest")
        loop = _loop(entra=entra)
        loop.contain(host=None, user="guest_partner.com#EXT#@example.org",
                     comment="test", disable_account=True, execute=True)
        self.assertEqual(len(entra.enabled_changes), 1)
        self.assertEqual(entra.enabled_changes[0][1], False)
        self.assertEqual(len(entra.revoked), 1)


class TestAudit(unittest.TestCase):
    def test_every_action_is_audited(self):
        path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        loop = _loop(audit_path=path)
        loop.contain(host="WS-1234", user="alice@example.org", comment="test", execute=True)
        with open(path, encoding="utf-8") as handle:
            lines = [ln for ln in handle.read().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2, "one audit record per half of the loop")

    def test_dry_run_is_audited_too(self):
        path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        loop = _loop(audit_path=path)
        loop.contain(host="WS-1234", user=None, comment="test", execute=False)
        with open(path, encoding="utf-8") as handle:
            self.assertIn('"mode":"dry-run"', handle.read())


class TestReporting(unittest.TestCase):
    def test_report_includes_saved_time(self):
        result = LoopResult(
            results=[
                ActionResult("mde.isolate", "WS-1", True, "execute", 300),
                ActionResult("entra.revoke", "a@b.c", True, "execute", 280),
            ],
            wall_clock_ms=310,
            mode="execute",
        )
        report = result.report()
        self.assertIn("Saved", report)
        self.assertEqual(result.serial_ms, 580)


if __name__ == "__main__":
    unittest.main(verbosity=2)
