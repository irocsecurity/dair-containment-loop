# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

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

Orient and Act are separate phases, and that separation is load-bearing. Both
targets are resolved and checked *before* either is acted on. If either target
is protected, nothing is changed. If either target cannot be resolved, nothing
is changed -- a partial containment is worse than none, because a responder who
sees one half succeed tends to assume the other did too.

Each phase is itself concurrent, so the cost of the separation is small: the
identity half may wait for the slower lookup before acting, but never for the
other half's action.

Once acting has begun, one API can still fail while the other succeeds. That
cannot be made atomic across two services; it is reported explicitly as a
failure rather than hidden.

Both actions are reversible, which is what makes unattended execution
appropriate. ``release`` implements the undo for both halves, also concurrently.
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

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


# -- target matching ----------------------------------------------------------


def _normalise(values: Iterable[str]) -> Set[str]:
    return {v.strip().lower() for v in values if v and v.strip()}


def _short_name(name: str) -> str:
    """Hostname without its domain suffix: ``dc01.corp.example.org`` -> ``dc01``."""
    return name.strip().lower().split(".", 1)[0]


def _device_is_protected(candidates: Iterable[str], protected: Set[str]) -> Optional[str]:
    """Return the first candidate that matches a protected device, else None.

    Matches on the full name *and* the short hostname. Defender reports
    domain-joined machines by FQDN, so an operator who protects ``DC01`` must be
    protected against ``dc01.corp.example.org``. This errs towards refusing more
    rather than less, which is the safe direction for a guardrail.
    """
    protected_short = {_short_name(p) for p in protected}
    for candidate in candidates:
        if not candidate or not candidate.strip():
            continue
        full = candidate.strip().lower()
        if full in protected or _short_name(full) in protected_short:
            return candidate
    return None


def _user_is_protected(candidates: Iterable[str], protected: Set[str]) -> Optional[str]:
    for candidate in candidates:
        if candidate and candidate.strip().lower() in protected:
            return candidate
    return None


def check_targets(
    host: Optional[str],
    user: Optional[str],
    protected_users: List[str],
    protected_devices: List[str],
) -> None:
    """Refuse protected targets using only what the operator typed.

    Pure, local, no network. This is the check that makes "a guardrail runs
    before any API is contacted" true for the common case, where the operator
    types the protected UPN or hostname directly.

    It cannot see through an object id or machine id to the identity behind it,
    so the loop checks again after resolution. Both checks are required.
    """
    if user and _user_is_protected([user], _normalise(protected_users)):
        raise ProtectedPrincipalError(
            f"REFUSED: {user} is on the protected-principal list (break-glass). "
            "No API was contacted and nothing was changed. "
            "Escalate to the Incident Commander."
        )
    if host and _device_is_protected([host], _normalise(protected_devices)):
        raise ProtectedPrincipalError(
            f"REFUSED: {host} is on the protected-device list. "
            "No API was contacted and nothing was changed. "
            "Escalate to the Incident Commander."
        )


# -- results ------------------------------------------------------------------


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
    skipped: bool = False

    @property
    def status(self) -> str:
        # A failure must never be labelled as something that would run. The
        # dry-run label is only earned by a half that resolved and passed.
        if self.skipped:
            return "NOT RUN"
        if not self.ok:
            return "FAILED"
        return "WOULD RUN" if self.mode == "dry-run" else "OK"

    def summary(self) -> str:
        line = f"[{self.status}] {self.action} -> {self.target} ({self.elapsed_ms} ms)"
        if self.error:
            line += f"\n         {'reason' if self.skipped else 'error'}: {self.error}"
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
        if not self.ok:
            # A time saving is only meaningful when containment actually
            # happened. Reporting one alongside a failure reads as success.
            lines.append("Timing comparison omitted: not every half completed.")
            return "\n".join(lines)
        lines.append(f"Sequential : {self.serial_ms} ms (what legacy ordering would have cost)")
        saved = self.serial_ms - self.wall_clock_ms
        if saved > 0:
            lines.append(f"Saved      : {saved} ms of adversary dwell time")
        return "\n".join(lines)


@dataclass
class _Orientation:
    """What the Orient phase learned about one half. Nothing has been changed."""

    half: str
    action: str
    target: str
    elapsed_ms: int
    subject: Dict[str, Any] = field(default_factory=dict)
    detail: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    refused: bool = False


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _run_concurrently(tasks: List[Callable[[], Any]]) -> List[Any]:
    """Run callables concurrently and return results in submission order."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        return list(pool.map(lambda task: task(), tasks))


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
        self._protected_users = sorted(_normalise(protected_users or []))
        self._protected_devices = sorted(_normalise(protected_devices or []))

        if require_guardrail:
            self._assert_guardrail_configured()

    # -- guardrails --------------------------------------------------------

    def _assert_guardrail_configured(self) -> None:
        """Fail closed if the protected-principal list is empty or templated."""
        validate_guardrails(self._protected_users, self._protected_devices)

    def _check_user(self, *names: str) -> None:
        """Post-resolution check: catches an object id that resolved to a protected UPN."""
        hit = _user_is_protected(names, set(self._protected_users))
        if hit:
            raise ProtectedPrincipalError(
                f"REFUSED: {hit} is on the protected-principal list (break-glass). "
                "Nothing was changed. Escalate to the Incident Commander."
            )

    def _check_device(self, *names: str) -> None:
        """Post-resolution check: catches a machine id or FQDN behind a protected name."""
        hit = _device_is_protected(names, set(self._protected_devices))
        if hit:
            raise ProtectedPrincipalError(
                f"REFUSED: {hit} is on the protected-device list. "
                "Nothing was changed. Escalate to the Incident Commander."
            )

    # -- audit -------------------------------------------------------------

    def _audit_result(self, result: ActionResult, outcome: Optional[str] = None) -> None:
        if outcome is None:
            outcome = "ok" if result.ok else ("not-executed" if result.skipped else "failed")
        self._audit.record(
            result.action,
            result.target,
            result.mode,
            outcome,
            reversible=result.reversible,
            undo_hint=result.undo_hint,
            detail={**result.detail, **({"error": result.error} if result.error else {})},
        )

    # -- orient: resolve and check, change nothing --------------------------

    def _orient_host(self, identifier: str, isolation_type: str) -> _Orientation:
        started = time.monotonic()
        target = identifier
        try:
            machine = self._mde.resolve_machine(identifier)
            target = machine.get("computerDnsName") or identifier
            self._check_device(identifier, target, machine.get("id", ""))

            existing = self._mde.active_isolation(machine["id"])
            if existing:
                LOG.warning(
                    "Machine %s is already isolated or has an isolation change in flight "
                    "(%s %s, id %s). Proceeding anyway; MDE will reconcile.",
                    target,
                    existing.get("type"),
                    existing.get("status"),
                    existing.get("id"),
                )

            return _Orientation(
                half="host",
                action="mde.isolate",
                target=target,
                elapsed_ms=_elapsed_ms(started),
                subject=machine,
                detail={
                    "machine_id": machine["id"],
                    "computer_dns_name": target,
                    "os": machine.get("osPlatform"),
                    "health": machine.get("healthStatus"),
                    "last_seen": machine.get("lastSeen"),
                    "isolation_type": isolation_type,
                },
            )
        except ProtectedPrincipalError as exc:
            return _Orientation(
                "host", "mde.isolate", target, _elapsed_ms(started), error=str(exc), refused=True
            )
        except (ApiError, MachineNotFound) as exc:
            return _Orientation("host", "mde.isolate", target, _elapsed_ms(started), error=str(exc))

    def _orient_user(self, identifier: str, disable_account: bool) -> _Orientation:
        started = time.monotonic()
        action = "entra.revoke+disable" if disable_account else "entra.revoke"
        target = identifier
        try:
            user = self._entra.resolve_user(identifier)
            target = user.get("userPrincipalName") or identifier
            self._check_user(identifier, target, user.get("id", ""))

            return _Orientation(
                half="user",
                action=action,
                target=target,
                elapsed_ms=_elapsed_ms(started),
                subject=user,
                detail={
                    "object_id": user["id"],
                    "upn": target,
                    "user_type": user.get("userType"),
                    "hybrid": bool(user.get("onPremisesSyncEnabled")),
                    "account_enabled_before": user.get("accountEnabled"),
                    "sessions_valid_from_before": user.get("signInSessionsValidFromDateTime"),
                    "disable_requested": disable_account,
                },
            )
        except ProtectedPrincipalError as exc:
            return _Orientation(
                "user", action, target, _elapsed_ms(started), error=str(exc), refused=True
            )
        except (ApiError, PrincipalNotFound) as exc:
            return _Orientation("user", action, target, _elapsed_ms(started), error=str(exc))

    # -- act: only reached when every half oriented cleanly ------------------

    def _act_host(self, o: _Orientation, comment: str, isolation_type: str) -> ActionResult:
        started = time.monotonic()
        detail = dict(o.detail)
        try:
            action = self._mde.isolate(o.subject["id"], comment, isolation_type)
            detail["machine_action_id"] = (action or {}).get("id")
            detail["action_status"] = (action or {}).get("status")
            error = None
        except ApiError as exc:
            error = str(exc)
        return ActionResult(
            action=o.action,
            target=o.target,
            ok=error is None,
            mode="execute",
            elapsed_ms=o.elapsed_ms + _elapsed_ms(started),
            undo_hint=f"dair-contain release --host {o.target}",
            detail=detail,
            error=error,
        )

    def _act_user(self, o: _Orientation, disable_account: bool) -> ActionResult:
        started = time.monotonic()
        detail = dict(o.detail)
        user = o.subject
        try:
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
            error = None
        except ApiError as exc:
            error = str(exc)
        return ActionResult(
            action=o.action,
            target=o.target,
            ok=error is None,
            mode="execute",
            elapsed_ms=o.elapsed_ms + _elapsed_ms(started),
            undo_hint=f"dair-contain release --user {o.target}",
            detail=detail,
            error=error,
        )

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
        """Resolve and check both halves, then act on both concurrently.

        Raises ProtectedPrincipalError if any target is protected, having
        changed nothing. Returns a failed LoopResult, having changed nothing, if
        any target cannot be resolved.
        """
        if not host and not user:
            raise ValueError("Specify at least one of host or user.")

        # Before any network call: refuse what the operator typed.
        check_targets(host, user, self._protected_users, self._protected_devices)

        mode = "execute" if execute else "dry-run"
        started = time.monotonic()

        # Orient -- both halves concurrently. Nothing is changed in this phase.
        orient: List[Callable[[], _Orientation]] = []
        if host:
            orient.append(lambda: self._orient_host(host, isolation_type))
        if user:
            orient.append(lambda: self._orient_user(user, disable_account))
        orientations: List[_Orientation] = _run_concurrently(orient)

        refused = [o for o in orientations if o.refused]
        if refused:
            for o in orientations:
                blocked = ActionResult(
                    o.action,
                    o.target,
                    False,
                    mode,
                    o.elapsed_ms,
                    detail=o.detail,
                    error=o.error or "not executed: another target was refused by the guardrail",
                    skipped=not o.refused,
                )
                self._audit_result(blocked, "refused" if o.refused else "not-executed")
            raise ProtectedPrincipalError(refused[0].error or "REFUSED by guardrail.")

        failed = [o for o in orientations if o.error]
        if failed:
            names = ", ".join(o.half for o in failed)
            results = [
                ActionResult(
                    o.action,
                    o.target,
                    False,
                    mode,
                    o.elapsed_ms,
                    detail=o.detail,
                    error=o.error
                    or (
                        f"not executed: the {names} target could not be resolved, and "
                        "containment only acts when every target resolves"
                    ),
                    skipped=not o.error,
                )
                for o in orientations
            ]
            for r in results:
                self._audit_result(r)
            return LoopResult(results, _elapsed_ms(started), mode)

        # Act -- both halves concurrently, only after every half oriented cleanly.
        if execute:
            act: List[Callable[[], ActionResult]] = []
            for o in orientations:
                if o.half == "host":
                    act.append(lambda o=o: self._act_host(o, comment, isolation_type))
                else:
                    act.append(lambda o=o: self._act_user(o, disable_account))
            results = _run_concurrently(act)
        else:
            results = [
                ActionResult(
                    o.action,
                    o.target,
                    True,
                    mode,
                    o.elapsed_ms,
                    undo_hint=f"dair-contain release --{o.half} {o.target}",
                    detail=o.detail,
                )
                for o in orientations
            ]

        for r in results:
            self._audit_result(r)

        results.sort(key=lambda r: 0 if r.action.startswith("mde") else 1)
        return LoopResult(results, _elapsed_ms(started), mode)

    def release(
        self,
        host: Optional[str],
        user: Optional[str],
        comment: str,
        enable_account: bool = False,
        execute: bool = False,
    ) -> LoopResult:
        """Reverse containment. Also concurrent -- restoration is time-critical too.

        Unlike ``contain``, release acts on whatever it can resolve. Restoring
        one half is strictly better than restoring neither, and re-enabling a
        protected account is a legitimate recovery step, so the guardrail does
        not apply here.
        """
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
                res = ActionResult(
                    "mde.release",
                    machine.get("computerDnsName", host),
                    True,
                    mode,
                    _elapsed_ms(started),
                    detail=detail,
                )
            except (ApiError, MachineNotFound) as exc:
                res = ActionResult(
                    "mde.release", host or "?", False, mode, _elapsed_ms(started), error=str(exc)
                )
            self._audit_result(res)
            return res

        def release_user() -> ActionResult:
            started = time.monotonic()
            mode = "execute" if execute else "dry-run"
            try:
                u = self._entra.resolve_user(user)  # type: ignore[arg-type]
                detail = {
                    "object_id": u["id"],
                    "upn": u.get("userPrincipalName"),
                    "account_enabled_before": u.get("accountEnabled"),
                }
                if execute and enable_account:
                    self._entra.set_account_enabled(u["id"], True)
                    detail["enabled"] = True
                res = ActionResult(
                    "entra.enable",
                    u.get("userPrincipalName", user),
                    True,
                    mode,
                    _elapsed_ms(started),
                    detail=detail,
                )
            except (ApiError, PrincipalNotFound) as exc:
                res = ActionResult(
                    "entra.enable", user or "?", False, mode, _elapsed_ms(started), error=str(exc)
                )
            self._audit_result(res)
            return res

        tasks: List[Callable[[], ActionResult]] = []
        if host:
            tasks.append(release_host)
        if user:
            tasks.append(release_user)

        started = time.monotonic()
        results = _run_concurrently(tasks)
        wall = _elapsed_ms(started)

        results.sort(key=lambda r: 0 if r.action.startswith("mde") else 1)
        return LoopResult(results, wall, "execute" if execute else "dry-run")
