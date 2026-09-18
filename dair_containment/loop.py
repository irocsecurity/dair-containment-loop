"""The DAIR Containment Loop.

Legacy incident response runs containment as a sequence: isolate the host, then
once that completes, revoke the user's sessions. In a credential-theft incident
that ordering is actively harmful -- the adversary holds a session that is
independent of the endpoint, so the seconds spent waiting on the endpoint action
are seconds the identity remains usable.

This module fires both halves **simultaneously** and joins on the results. The
identity half does not wait for the endpoint half, and neither blocks scoping.

    Observe  -> a host and a principal are implicated
    Orient   -> resolve both, check protected-principal guardrails
    Decide   -> apply the reversibility test (both actions here pass it)
    Act      -> execute concurrently, audit, report

Both actions are reversible, which is what makes unattended execution
appropriate. ``release`` implements the undo for both halves, also concurrently.
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .audit import AuditLog
from .client import ApiError
from .defender import DefenderClient, MachineNotFound
from .entra import EntraClient, PrincipalNotFound

LOG = logging.getLogger(__name__)


class ProtectedPrincipalError(RuntimeError):
    """A guardrail refused to act on a protected identity or device."""


class GuardrailNotConfigured(RuntimeError):
    """The protected-principal guardrail is unconfigured and would be inert."""


# Template values shipped in the example config. If these are still present at
# runtime the guardrail has never been populated, which means it would silently
# fail open against this tenant's real break-glass accounts.
_TEMPLATE_MARKERS = ("contoso.onmicrosoft.com", "example.com", "CHANGE-ME")


def validate_guardrails(protected_users: List[str], protected_devices: List[str]) -> None:
    """Validate the protected-principal guardrail. Pure, local, no network.

    Exposed at module level so the CLI can run this *before* constructing an
    auth client, keeping the cheapest and most safety-critical check first.

    An empty or template-filled guardrail is worse than no guardrail, because it
    looks like protection. This tool can disable accounts and cut devices off
    the network; it refuses to run until the operator has stated which
    identities are off limits.
    """
    users = [u.strip() for u in protected_users if u.strip()]
    if not users:
        raise GuardrailNotConfigured(
            "No protected principals configured. Populate 'protected_users' with this "
            "tenant's break-glass accounts before running containment. "
            "Override with --no-guardrail only if you have accepted that risk explicitly."
        )

    joined = ",".join(users + [d.strip() for d in protected_devices]).lower()
    for marker in _TEMPLATE_MARKERS:
        if marker.lower() in joined:
            raise GuardrailNotConfigured(
                f"Protected-principal list still contains template values ({marker!r}). "
                "Replace them with real break-glass accounts before running containment."
            )


@dataclass
class ActionResult:
    """Outcome of one half of the loop."""

    action: str
    target: str
    ok: bool
    mode: str
    elapsed_ms: int
    reversible: bool = True
    undo_hint: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def summary(self) -> str:
        status = "OK" if self.ok else "FAILED"
        if self.mode == "dry-run":
            status = "WOULD RUN"
        line = f"[{status}] {self.action} -> {self.target} ({self.elapsed_ms} ms)"
        if self.error:
            line += f"\n         error: {self.error}"
        return line


@dataclass
class LoopResult:
    results: List[ActionResult]
    wall_clock_ms: int
    mode: str

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results)

    @property
    def serial_ms(self) -> int:
        """What this would have cost run sequentially."""
        return sum(r.elapsed_ms for r in self.results)

    def report(self) -> str:
        lines = [r.summary() for r in self.results]
        lines.append("")
        lines.append(f"Wall clock : {self.wall_clock_ms} ms (concurrent)")
        lines.append(f"Sequential : {self.serial_ms} ms (what legacy ordering would have cost)")
        saved = self.serial_ms - self.wall_clock_ms
        if saved > 0:
            lines.append(f"Saved      : {saved} ms of adversary dwell time")
        return "\n".join(lines)


class ContainmentLoop:
    """Concurrent endpoint + identity containment."""

    def __init__(
        self,
        defender: DefenderClient,
        entra: EntraClient,
        audit: AuditLog,
        protected_users: Optional[List[str]] = None,
        protected_devices: Optional[List[str]] = None,
        require_guardrail: bool = True,
    ) -> None:
        self._mde = defender
        self._entra = entra
        self._audit = audit
        self._protected_users = [u.strip().lower() for u in (protected_users or []) if u.strip()]
        self._protected_devices = [d.strip().lower() for d in (protected_devices or []) if d.strip()]

        if require_guardrail:
            self._assert_guardrail_configured()

    # -- guardrails --------------------------------------------------------

    def _assert_guardrail_configured(self) -> None:
        """Fail closed if the protected-principal list is empty or templated."""
        validate_guardrails(self._protected_users, self._protected_devices)

    def _check_user(self, upn: str) -> None:
        if upn.strip().lower() in self._protected_users:
            raise ProtectedPrincipalError(
                f"REFUSED: {upn} is on the protected-principal list (break-glass). "
                "Escalate to the Incident Commander."
            )

    def _check_device(self, name: str) -> None:
        if name.strip().lower() in self._protected_devices:
            raise ProtectedPrincipalError(
                f"REFUSED: {name} is on the protected-device list. "
                "Escalate to the Incident Commander."
            )

    # -- halves ------------------------------------------------------------

    def _isolate_host(
        self, identifier: str, comment: str, isolation_type: str, execute: bool
    ) -> ActionResult:
        started = time.monotonic()
        mode = "execute" if execute else "dry-run"
        try:
            machine = self._mde.resolve_machine(identifier)
            machine_id = machine["id"]
            dns_name = machine.get("computerDnsName", identifier)
            self._check_device(dns_name)

            existing = self._mde.active_isolation(machine_id)
            if existing and existing.get("status") in ("Pending", "InProgress", "Succeeded"):
                LOG.warning(
                    "Machine %s already has an isolation action (%s, status=%s). Proceeding anyway; "
                    "MDE will reconcile.",
                    dns_name, existing.get("id"), existing.get("status"),
                )

            detail: Dict[str, Any] = {
                "machine_id": machine_id,
                "computer_dns_name": dns_name,
                "os": machine.get("osPlatform"),
                "health": machine.get("healthStatus"),
                "last_seen": machine.get("lastSeen"),
                "isolation_type": isolation_type,
            }

            if execute:
                action = self._mde.isolate(machine_id, comment, isolation_type)
                detail["machine_action_id"] = (action or {}).get("id")
                detail["action_status"] = (action or {}).get("status")

            elapsed = int((time.monotonic() - started) * 1000)
            result = ActionResult(
                action="mde.isolate",
                target=dns_name,
                ok=True,
                mode=mode,
                elapsed_ms=elapsed,
                reversible=True,
                undo_hint=f"dair-contain release --host {dns_name}",
                detail=detail,
            )
        except (ApiError, MachineNotFound, ProtectedPrincipalError) as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            result = ActionResult(
                action="mde.isolate",
                target=identifier,
                ok=False,
                mode=mode,
                elapsed_ms=elapsed,
                reversible=True,
                error=str(exc),
            )

        self._audit.record(
            result.action, result.target, result.mode,
            "ok" if result.ok else "failed",
            reversible=result.reversible, undo_hint=result.undo_hint,
            detail={**result.detail, **({"error": result.error} if result.error else {})},
        )
        return result

    def _contain_identity(
        self, identifier: str, disable_account: bool, execute: bool
    ) -> ActionResult:
        started = time.monotonic()
        mode = "execute" if execute else "dry-run"
        action_name = "entra.revoke+disable" if disable_account else "entra.revoke"
        try:
            user = self._entra.resolve_user(identifier)
            upn = user.get("userPrincipalName", identifier)
            self._check_user(upn)

            detail: Dict[str, Any] = {
                "object_id": user["id"],
                "upn": upn,
                "user_type": user.get("userType"),
                "hybrid": bool(user.get("onPremisesSyncEnabled")),
                "account_enabled_before": user.get("accountEnabled"),
                "sessions_valid_from_before": user.get("signInSessionsValidFromDateTime"),
                "disable_requested": disable_account,
            }

            if execute:
                # Guests: disable first, then revoke. Revoking a guest's sessions
                # without disabling the object achieves nothing -- the home tenant
                # re-issues via SSO immediately.
                if disable_account and user.get("userType") == "Guest":
                    self._entra.set_account_enabled(user["id"], False)
                    detail["disabled"] = True
                    self._entra.revoke_sessions(user["id"])
                    detail["revoked"] = True
                else:
                    self._entra.revoke_sessions(user["id"])
                    detail["revoked"] = True
                    if disable_account:
                        self._entra.set_account_enabled(user["id"], False)
                        detail["disabled"] = True

                detail["sessions_valid_from_after"] = self._entra.sessions_valid_from(user["id"])

            undo = f"dair-contain release --user {upn}"
            elapsed = int((time.monotonic() - started) * 1000)
            result = ActionResult(
                action=action_name,
                target=upn,
                ok=True,
                mode=mode,
                elapsed_ms=elapsed,
                reversible=True,
                undo_hint=undo,
                detail=detail,
            )
        except (ApiError, PrincipalNotFound, ProtectedPrincipalError) as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            result = ActionResult(
                action=action_name,
                target=identifier,
                ok=False,
                mode=mode,
                elapsed_ms=elapsed,
                reversible=True,
                error=str(exc),
            )

        self._audit.record(
            result.action, result.target, result.mode,
            "ok" if result.ok else "failed",
            reversible=result.reversible, undo_hint=result.undo_hint,
            detail={**result.detail, **({"error": result.error} if result.error else {})},
        )
        return result

    # -- public API --------------------------------------------------------

    def contain(
        self,
        host: Optional[str],
        user: Optional[str],
        comment: str,
        isolation_type: str = "full",
        disable_account: bool = False,
        execute: bool = False,
    ) -> LoopResult:
        """Run both halves of the containment loop concurrently."""
        if not host and not user:
            raise ValueError("Specify at least one of host or user.")

        tasks = []
        if host:
            tasks.append(("host", lambda: self._isolate_host(host, comment, isolation_type, execute)))
        if user:
            tasks.append(("user", lambda: self._contain_identity(user, disable_account, execute)))

        started = time.monotonic()
        results: List[ActionResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks}
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        wall = int((time.monotonic() - started) * 1000)

        # Stable ordering for reporting: endpoint first, then identity.
        results.sort(key=lambda r: 0 if r.action.startswith("mde") else 1)
        return LoopResult(results=results, wall_clock_ms=wall, mode="execute" if execute else "dry-run")

    def release(
        self,
        host: Optional[str],
        user: Optional[str],
        comment: str,
        enable_account: bool = False,
        execute: bool = False,
    ) -> LoopResult:
        """Reverse containment. Also concurrent -- restoration is time-critical too."""
        if not host and not user:
            raise ValueError("Specify at least one of host or user.")

        def release_host() -> ActionResult:
            started = time.monotonic()
            mode = "execute" if execute else "dry-run"
            try:
                machine = self._mde.resolve_machine(host)  # type: ignore[arg-type]
                detail: Dict[str, Any] = {
                    "machine_id": machine["id"],
                    "computer_dns_name": machine.get("computerDnsName"),
                }
                if execute:
                    action = self._mde.release(machine["id"], comment)
                    detail["machine_action_id"] = (action or {}).get("id")
                elapsed = int((time.monotonic() - started) * 1000)
                res = ActionResult("mde.release", machine.get("computerDnsName", host), True, mode, elapsed, detail=detail)
            except (ApiError, MachineNotFound) as exc:
                elapsed = int((time.monotonic() - started) * 1000)
                res = ActionResult("mde.release", host or "?", False, mode, elapsed, error=str(exc))
            self._audit.record(res.action, res.target, res.mode, "ok" if res.ok else "failed",
                               reversible=True, detail={**res.detail, **({"error": res.error} if res.error else {})})
            return res

        def release_user() -> ActionResult:
            started = time.monotonic()
            mode = "execute" if execute else "dry-run"
            try:
                u = self._entra.resolve_user(user)  # type: ignore[arg-type]
                detail = {"object_id": u["id"], "upn": u.get("userPrincipalName"),
                          "account_enabled_before": u.get("accountEnabled")}
                if execute and enable_account:
                    self._entra.set_account_enabled(u["id"], True)
                    detail["enabled"] = True
                elapsed = int((time.monotonic() - started) * 1000)
                res = ActionResult("entra.enable", u.get("userPrincipalName", user), True, mode, elapsed, detail=detail)
            except (ApiError, PrincipalNotFound) as exc:
                elapsed = int((time.monotonic() - started) * 1000)
                res = ActionResult("entra.enable", user or "?", False, mode, elapsed, error=str(exc))
            self._audit.record(res.action, res.target, res.mode, "ok" if res.ok else "failed",
                               reversible=True, detail={**res.detail, **({"error": res.error} if res.error else {})})
            return res

        tasks = []
        if host:
            tasks.append(release_host)
        if user:
            tasks.append(release_user)

        started = time.monotonic()
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            for future in concurrent.futures.as_completed([pool.submit(t) for t in tasks]):
                results.append(future.result())
        wall = int((time.monotonic() - started) * 1000)

        results.sort(key=lambda r: 0 if r.action.startswith("mde") else 1)
        return LoopResult(results=results, wall_clock_ms=wall, mode="execute" if execute else "dry-run")
