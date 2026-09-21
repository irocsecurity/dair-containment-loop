# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for the containment loop. No network, no tenant required.

Run with:  python -m pytest -q     (or)     python tests/test_loop.py
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dair_containment import cli  # noqa: E402
from dair_containment.audit import AuditLog  # noqa: E402
from dair_containment.auth import (  # noqa: E402
    GRAPH_RESOURCE,
    MDE_RESOURCE,
    AppCredentials,
    AuthError,
    TokenProvider,
    token_roles,
)
from dair_containment.client import ApiError  # noqa: E402
from dair_containment.defender import DefenderClient, MachineNotFound  # noqa: E402
from dair_containment.entra import EntraClient  # noqa: E402
from dair_containment.loop import (  # noqa: E402
    ActionResult,
    ContainmentLoop,
    GuardrailNotConfigured,
    LoopResult,
    ProtectedPrincipalError,
)


class FakeDefender:
    """Stands in for DefenderClient with a deliberate 200 ms latency."""

    def __init__(self, dns_name=None, fail_with=None):
        self.isolated = []
        self.released = []
        self.lookups = []
        self._dns_name = dns_name
        self._fail_with = fail_with

    def resolve_machine(self, identifier):
        self.lookups.append(identifier)
        time.sleep(0.2)
        if self._fail_with:
            raise self._fail_with
        return {
            "id": "a" * 40,
            "computerDnsName": self._dns_name or identifier,
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

    def __init__(self, user_type="Member", upn=None, fail_with=None):
        self.revoked = []
        self.enabled_changes = []
        self.lookups = []
        self._user_type = user_type
        self._upn = upn
        self._fail_with = fail_with

    def resolve_user(self, identifier):
        self.lookups.append(identifier)
        time.sleep(0.2)
        if self._fail_with:
            raise self._fail_with
        return {
            "id": "11111111-2222-3333-4444-555555555555",
            "userPrincipalName": self._upn or identifier,
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
        with self.assertRaises(ProtectedPrincipalError) as ctx:
            loop.contain(
                host=None, user="bg-admin@realtenant.onmicrosoft.com", comment="test", execute=True
            )
        self.assertIn("protected-principal list", str(ctx.exception))
        self.assertEqual(entra.revoked, [], "protected principal must not be revoked")

    def test_protected_device_is_refused(self):
        mde = FakeDefender()
        loop = _loop(mde=mde, protected_devices=["DC01"])
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="DC01", user=None, comment="test", execute=True)
        self.assertEqual(mde.isolated, [], "protected device must not be isolated")


class TestDryRun(unittest.TestCase):
    def test_dry_run_performs_no_mutations(self):
        mde, entra = FakeDefender(), FakeEntra()
        loop = _loop(mde=mde, entra=entra)
        result = loop.contain(
            host="WS-1234", user="alice@example.org", comment="test", execute=False
        )
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
        result = loop.contain(
            host="WS-1234", user="alice@example.org", comment="test", execute=True
        )
        self.assertTrue(result.ok, msg=result.report())
        self.assertLess(
            result.wall_clock_ms,
            result.serial_ms * 0.8,  # headroom for contended CI runners
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
        loop.contain(
            host=None,
            user="guest_partner.com#EXT#@example.org",
            comment="test",
            disable_account=True,
            execute=True,
        )
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


PROTECTED_UPN = "bg-admin@realtenant.onmicrosoft.com"
OBJECT_ID = "99999999-8888-7777-6666-555555555555"


class TestGuardrailOrdering(unittest.TestCase):
    """Lab finding #6: the guardrail must run first, and must stop both halves."""

    def test_typed_protected_user_is_refused_before_any_lookup(self):
        entra = FakeEntra()
        loop = _loop(entra=entra)
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host=None, user=PROTECTED_UPN, comment="t", execute=True)
        self.assertEqual(entra.lookups, [], "no API may be contacted for a typed protected UPN")

    def test_typed_protected_device_is_refused_before_any_lookup(self):
        mde = FakeDefender()
        loop = _loop(mde=mde)
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="DC01", user=None, comment="t", execute=True)
        self.assertEqual(mde.lookups, [], "no API may be contacted for a typed protected device")

    def test_object_id_resolving_to_protected_user_is_refused(self):
        """The pre-network check cannot see through an object id; the post-resolve one must."""
        entra = FakeEntra(upn=PROTECTED_UPN)
        loop = _loop(entra=entra)
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host=None, user=OBJECT_ID, comment="t", execute=True)
        self.assertEqual(entra.lookups, [OBJECT_ID])
        self.assertEqual(entra.revoked, [])

    def test_refusing_the_user_does_not_isolate_the_host(self):
        """The core regression. Previously the host was isolated while the user was refused."""
        mde, entra = FakeDefender(), FakeEntra(upn=PROTECTED_UPN)
        loop = _loop(mde=mde, entra=entra)
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="WS-1234", user=OBJECT_ID, comment="t", execute=True)
        self.assertEqual(mde.isolated, [], "a refusal on one half must stop the other half")
        self.assertEqual(entra.revoked, [])

    def test_refusing_the_host_does_not_revoke_the_user(self):
        mde, entra = FakeDefender(dns_name="dc01.corp.example.org"), FakeEntra()
        loop = _loop(mde=mde, entra=entra)
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="a" * 40, user="alice@example.org", comment="t", execute=True)
        self.assertEqual(entra.revoked, [], "a refusal on one half must stop the other half")
        self.assertEqual(mde.isolated, [])

    def test_short_protected_name_covers_fqdn(self):
        """Protecting DC01 must protect dc01.corp.example.org, as Defender reports it."""
        mde = FakeDefender(dns_name="dc01.corp.example.org")
        loop = _loop(mde=mde, protected_devices=["DC01"])
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="a" * 40, user=None, comment="t", execute=True)
        self.assertEqual(mde.isolated, [])

    def test_typed_fqdn_of_protected_short_name_refused_before_lookup(self):
        mde = FakeDefender()
        loop = _loop(mde=mde, protected_devices=["DC01"])
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="DC01.corp.example.org", user=None, comment="t", execute=True)
        self.assertEqual(mde.lookups, [])

    def test_refusal_is_audited(self):
        path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        loop = _loop(entra=FakeEntra(upn=PROTECTED_UPN), audit_path=path)
        with self.assertRaises(ProtectedPrincipalError):
            loop.contain(host="WS-1234", user=OBJECT_ID, comment="t", execute=True)
        with open(path, encoding="utf-8") as handle:
            records = [json.loads(ln) for ln in handle if ln.strip()]
        outcomes = sorted(r["result"] for r in records)
        self.assertEqual(outcomes, ["not-executed", "refused"])


class TestPartialContainment(unittest.TestCase):
    """If either target cannot be resolved, nothing is changed."""

    def test_unresolvable_user_blocks_host_isolation(self):
        denied = ApiError("GET /users/x -> HTTP 403", status_code=403)
        mde, entra = FakeDefender(), FakeEntra(fail_with=denied)
        result = _loop(mde=mde, entra=entra).contain(
            host="WS-1234", user="alice@example.org", comment="t", execute=True
        )
        self.assertFalse(result.ok)
        self.assertEqual(mde.isolated, [], "host must not be isolated when the user half failed")
        host_result = next(r for r in result.results if r.action == "mde.isolate")
        self.assertTrue(host_result.skipped)
        self.assertIn("NOT RUN", host_result.summary())

    def test_unresolvable_host_blocks_revocation(self):
        missing = MachineNotFound("no such machine", status_code=404)
        mde, entra = FakeDefender(fail_with=missing), FakeEntra()
        result = _loop(mde=mde, entra=entra).contain(
            host="WS-9999", user="alice@example.org", comment="t", execute=True
        )
        self.assertFalse(result.ok)
        self.assertEqual(entra.revoked, [], "user must not be revoked when the host half failed")


class TestDryRunReporting(unittest.TestCase):
    """Lab finding #4: a failed half must never read as something that would run."""

    def _failed_dry_run(self):
        denied = ApiError("GET /users/x -> HTTP 403", status_code=403)
        return _loop(entra=FakeEntra(fail_with=denied)).contain(
            host="WS-1234", user="alice@example.org", comment="t", execute=False
        )

    def test_failed_half_is_not_labelled_would_run(self):
        result = self._failed_dry_run()
        user_result = next(r for r in result.results if r.action.startswith("entra"))
        self.assertIn("[FAILED]", user_result.summary())
        self.assertNotIn("WOULD RUN", user_result.summary())

    def test_no_half_is_labelled_would_run_when_the_run_cannot_act(self):
        self.assertNotIn("WOULD RUN", self._failed_dry_run().report())

    def test_report_omits_time_saved_when_not_ok(self):
        report = self._failed_dry_run().report()
        self.assertNotIn("Saved", report)
        self.assertNotIn("Sequential", report)

    def test_clean_dry_run_still_says_would_run(self):
        result = _loop().contain(host="WS-1234", user="alice@example.org", comment="t")
        self.assertTrue(result.ok)
        self.assertEqual(result.report().count("[WOULD RUN]"), 2)


def _fake_jwt(claims):
    def encode(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{encode({'alg': 'none'})}.{encode(claims)}.sig"


class TestAuth(unittest.TestCase):
    """Lab findings #1 (key via environment) and #2 (preflight checks granted roles)."""

    ENV = {
        "DAIR_TENANT_ID": "00000000-0000-0000-0000-000000000001",
        "DAIR_CLIENT_ID": "00000000-0000-0000-0000-000000000002",
        "DAIR_CERT_THUMBPRINT": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
    }
    PEM = "-----BEGIN PRIVATE KEY-----\nMIIfake\n-----END PRIVATE KEY-----\n"

    def _env(self, **extra):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("DAIR_")}
        return mock.patch.dict(os.environ, {**clean, **self.ENV, **extra}, clear=True)

    def test_key_from_environment_needs_no_file(self):
        with self._env(DAIR_CERT_PEM=self.PEM):
            creds = AppCredentials.from_env()
        self.assertIsNone(creds.certificate_path)
        self.assertEqual(creds._msal_credential()["private_key"], self.PEM)

    def test_escaped_newlines_in_key_are_restored(self):
        with self._env(DAIR_CERT_PEM=self.PEM.replace("\n", "\\n")):
            creds = AppCredentials.from_env()
        self.assertEqual(creds.certificate_pem, self.PEM)

    def test_value_that_is_not_a_key_is_rejected(self):
        # Must fail on the *content* of DAIR_CERT_PEM, not merely because no
        # credential was found -- the old code raised the latter by ignoring it.
        with self._env(DAIR_CERT_PEM="not a key"), self.assertRaises(AuthError) as ctx:
            AppCredentials.from_env()
        self.assertIn("private key", str(ctx.exception))

    def test_key_and_secret_never_appear_in_repr(self):
        # noqa justification: a deliberately fake value, asserted absent from repr below.
        with self._env(DAIR_CERT_PEM=self.PEM, DAIR_CLIENT_SECRET="s3cr3t-value"):  # noqa: S106
            text = repr(AppCredentials.from_env())
        self.assertNotIn("MIIfake", text)
        self.assertNotIn("s3cr3t-value", text)

    def test_token_roles_reads_the_roles_claim(self):
        token = _fake_jwt({"roles": ["Machine.Read.All", "Machine.Isolate"]})
        self.assertEqual(token_roles(token), {"Machine.Read.All", "Machine.Isolate"})

    def test_token_roles_rejects_a_non_jwt(self):
        with self.assertRaises(AuthError):
            token_roles("not-a-jwt")

    def _provider(self, graph_roles, mde_roles):
        provider = TokenProvider.__new__(TokenProvider)
        tokens = {
            GRAPH_RESOURCE: _fake_jwt({"roles": graph_roles}),
            MDE_RESOURCE: _fake_jwt({"roles": mde_roles}),
        }
        provider.get_token = tokens.__getitem__  # type: ignore[method-assign]
        return provider

    def test_preflight_fails_when_consent_was_never_granted(self):
        """A token with no roles is exactly what an un-consented app receives."""
        with self.assertRaises(AuthError) as ctx:
            self._provider([], []).preflight()
        self.assertIn("User.ReadWrite.All", str(ctx.exception))
        self.assertIn("Machine.Isolate", str(ctx.exception))

    def test_preflight_fails_when_one_role_is_missing(self):
        with self.assertRaises(AuthError) as ctx:
            self._provider(["User.ReadWrite.All"], ["Machine.Read.All"]).preflight()
        self.assertIn("Machine.Isolate", str(ctx.exception))
        self.assertNotIn("User.ReadWrite.All", str(ctx.exception))

    def test_preflight_passes_with_required_roles(self):
        provider = self._provider(["User.ReadWrite.All"], ["Machine.Read.All", "Machine.Isolate"])
        self.assertEqual(set(provider.preflight().values()), {True})


class TestResolutionVisibility(unittest.TestCase):
    """Lab finding #5: a dry run must show what the user identifier resolved to."""

    def test_user_resolution_is_logged(self):
        client = EntraClient.__new__(EntraClient)
        client.get = lambda path, params=None: {  # type: ignore[method-assign]
            "id": OBJECT_ID,
            "userPrincipalName": "alice@example.org",
            "userType": "Member",
            "accountEnabled": True,
            "onPremisesSyncEnabled": False,
        }
        with self.assertLogs("dair_containment.entra", level="INFO") as logs:
            client.resolve_user("alice@example.org")
        line = "\n".join(logs.output)
        self.assertIn("Resolved 'alice@example.org' -> user " + OBJECT_ID, line)
        self.assertIn("type=Member", line)


def _defender(inventory):
    """A DefenderClient whose HTTP layer serves a fixed device inventory.

    Mirrors MDE's behaviour: /machines/{id} returns one device or 404, and the
    startswith() filter returns every device whose name begins with the prefix.
    """
    client = DefenderClient.__new__(DefenderClient)
    client.calls = []

    def get(path, params=None):
        client.calls.append((path, params))
        if path.startswith("/machines/"):
            wanted = path.rsplit("/", 1)[1]
            for m in inventory:
                if m["id"] == wanted:
                    return m
            raise ApiError("not found", status_code=404)
        prefix = params["$filter"].split("'")[1]
        return {"value": [m for m in inventory if m["computerDnsName"].startswith(prefix)]}

    client.get = get
    return client


def _device(name, machine_id="b" * 40, last_seen="2026-09-21T00:00:00Z"):
    return {
        "id": machine_id,
        "computerDnsName": name,
        "healthStatus": "Active",
        "lastSeen": last_seen,
    }


class TestDeviceResolution(unittest.TestCase):
    """Lab findings #10 and #11: exact matching, safe input, visible resolution."""

    def test_prefix_is_never_accepted_as_a_match(self):
        """The core regression. 'WS-12' previously resolved to ws-1234."""
        mde = _defender([_device("ws-1234")])
        with self.assertRaises(MachineNotFound) as ctx:
            mde.resolve_machine("WS-12")
        self.assertIn("ws-1234", str(ctx.exception), "near misses should be listed, not chosen")

    def test_exact_short_name_matches_an_fqdn_record(self):
        mde = _defender([_device("lab-dair1.corp.local")])
        self.assertEqual(
            mde.resolve_machine("LAB-DAIR1")["computerDnsName"], "lab-dair1.corp.local"
        )

    def test_fqdn_input_selects_that_exact_device(self):
        """Two domains, same short name: an FQDN must not be overridden by recency."""
        older = _device("dc01.corp.a", machine_id="a" * 40, last_seen="2026-01-01T00:00:00Z")
        newer = _device("dc01.corp.b", machine_id="c" * 40, last_seen="2026-09-01T00:00:00Z")
        mde = _defender([older, newer])
        self.assertEqual(mde.resolve_machine("dc01.corp.a")["id"], "a" * 40)

    def test_filter_breaking_characters_are_rejected_before_any_query(self):
        mde = _defender([_device("ws-1234")])
        injected = "x') or startswith(computerDnsName,'"
        with self.assertRaises(MachineNotFound):
            mde.resolve_machine(injected)
        self.assertEqual(mde.calls, [], "a malformed name must not reach the API")

    def test_machine_id_resolution_is_logged(self):
        machine_id = "d" * 40
        mde = _defender([_device("lab-dair1", machine_id=machine_id)])
        with self.assertLogs("dair_containment.defender", level="INFO") as logs:
            mde.resolve_machine(machine_id)
        self.assertIn(f"Resolved '{machine_id}' -> machine {machine_id} (lab-dair1", logs.output[0])


class TestCliExitCodes(unittest.TestCase):
    """Lab finding #3 and the CLI half of #6. Each exit code must mean one thing."""

    def _run(self, argv, config=None):
        workdir = tempfile.mkdtemp()
        if config is not None:
            path = os.path.join(workdir, "c.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(config if isinstance(config, str) else json.dumps(config))
            argv = [*argv, "--config", path]
        clean = {k: v for k, v in os.environ.items() if not k.startswith("DAIR_")}
        quiet = contextlib.redirect_stderr(io.StringIO())
        with mock.patch.dict(os.environ, clean, clear=True), quiet:
            return cli.main(argv)

    def test_missing_config_is_a_usage_error(self):
        code = cli.main(["contain", "--host", "WS-1", "--config", "/nonexistent/c.json"])
        self.assertEqual(code, 64)

    def test_malformed_config_is_a_usage_error(self):
        self.assertEqual(self._run(["contain", "--host", "WS-1"], config="{not json"), 64)

    def test_string_instead_of_list_is_refused(self):
        """list('me@x.com') would silently become a list of characters."""
        config = {"protected_users": PROTECTED_UPN}
        self.assertEqual(self._run(["contain", "--host", "WS-1"], config=config), 64)

    def test_protected_target_refused_before_authentication(self):
        """No credentials are set. Exit 2 would mean the guardrail ran after auth."""
        config = {"protected_users": [PROTECTED_UPN], "protected_devices": []}
        code = self._run(["contain", "--user", PROTECTED_UPN, "--execute", "--yes"], config=config)
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
