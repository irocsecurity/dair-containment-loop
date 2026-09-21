# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Command-line interface for the DAIR Containment Loop.

Safety posture:

  * Dry-run is the DEFAULT. Nothing acts without ``--execute``.
  * ``--execute`` prompts for confirmation unless ``--yes`` is supplied.
  * The protected-principal guardrail must be populated or the tool refuses.
  * Every action, including dry-runs, is written to the audit log.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .audit import AuditLog
from .auth import AppCredentials, AuthError, TokenProvider
from .client import ApiError
from .defender import (
    ISOLATION_TYPES,
    DefenderClient,
    IsolationState,
    action_duration_s,
    isolation_state,
    parse_mde_time,
)
from .entra import EntraClient
from .loop import (
    ContainmentLoop,
    GuardrailNotConfigured,
    ProtectedPrincipalError,
    check_targets,
    validate_guardrails,
)

LOG = logging.getLogger("dair_containment")

# Exit codes. Wrappers -- SOAR playbooks, scripts run at 2 a.m. -- branch on
# these, so each must mean exactly one thing.
EXIT_OK = 0
EXIT_ACTION_FAILED = 1
EXIT_AUTH = 2
EXIT_GUARDRAIL = 3
EXIT_USAGE = 64
EXIT_ABORTED = 130


class ConfigError(ValueError):
    """The guardrail config is missing or malformed. A usage error, not a failed action."""


BANNER = r"""
  DAIR CONTAINMENT LOOP
  Endpoint isolation + identity revocation, executed concurrently.
"""


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # msal and urllib3 are noisy and can echo request metadata at DEBUG.
    logging.getLogger("msal").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _string_list(loaded: Dict, key: str, path: str) -> List[str]:
    """Read a list of strings, refusing anything else.

    A bare string must not be accepted: ``list("me@x.com")`` is a list of single
    characters, which would make the guardrail look populated while protecting
    nothing.
    """
    value = loaded.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' in {path} must be a JSON list of strings.")
    return list(value)


def _load_guardrails(path: Optional[str]) -> Dict[str, List[str]]:
    """Load protected principals from JSON config, then environment overlay."""
    data: Dict[str, List[str]] = {"protected_users": [], "protected_devices": []}

    if path:
        if not os.path.isfile(path):
            raise ConfigError(f"Config file not found: {path}")
        try:
            with open(path, encoding="utf-8") as handle:
                loaded = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Config file is not valid JSON: {path} ({exc})") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"Config file must contain a JSON object: {path}")
        data["protected_users"] = _string_list(loaded, "protected_users", path)
        data["protected_devices"] = _string_list(loaded, "protected_devices", path)

    env_users = os.environ.get("DAIR_PROTECTED_USERS", "")
    env_devices = os.environ.get("DAIR_PROTECTED_DEVICES", "")
    if env_users:
        data["protected_users"] += [u for u in env_users.split(",") if u.strip()]
    if env_devices:
        data["protected_devices"] += [d for d in env_devices.split(",") if d.strip()]

    return data


def _confirm(prompt: str) -> Optional[str]:
    """Ask the operator to type the word YES. Return None if confirmed, else why not.

    The deliberateness comes from typing the whole word, so any capitalisation
    is accepted. A bare "y" is not: a single keypress is what fingers do on
    autopilot, and that reflex is exactly what this prompt exists to interrupt.
    """
    try:
        answer = input(f"{prompt} [type YES to proceed]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return "no confirmation was received"
    if answer.lower() == "yes":
        return None
    return f"confirmation must be the word YES (received {answer[:20]!r})"


def _common_options() -> argparse.ArgumentParser:
    """Options shared by every subcommand.

    Attached via ``parents=`` to the subparsers rather than the top-level
    parser, so they are accepted in the position operators actually type them:
    ``dair-contain contain --host WS-1 --config c.json --execute``.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Path to JSON config with protected principals.")
    common.add_argument(
        "--audit-log", default="./dair-audit.jsonl", help="Audit trail path (JSONL)."
    )
    common.add_argument("--execute", action="store_true", help="Actually perform actions.")
    common.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    common.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    common.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    common.add_argument(
        "--no-guardrail",
        action="store_true",
        help="Disable the protected-principal safety check. Strongly discouraged.",
    )
    return common


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dair-contain",
        description="Concurrent endpoint isolation (Defender for Endpoint) and "
        "identity containment (Entra ID), implementing the DAIR Containment Loop.",
        epilog="Dry-run by default. Pass --execute to act.",
    )
    common = _common_options()
    sub = parser.add_subparsers(dest="command", required=True)

    contain = sub.add_parser(
        "contain", parents=[common], help="Isolate host and revoke identity, concurrently."
    )
    contain.add_argument("--host", help="Device hostname or MDE machine id.")
    contain.add_argument("--user", help="User principal name or Entra object id.")
    contain.add_argument(
        "--comment",
        default="DAIR containment loop - automated response",
        help="Comment recorded on the MDE machine action.",
    )
    contain.add_argument(
        "--isolation-type",
        choices=ISOLATION_TYPES,
        default="full",
        help="'selective' preserves Outlook/Teams/Skype connectivity.",
    )
    contain.add_argument(
        "--disable-account",
        action="store_true",
        help="Also set accountEnabled=false. Required for guest/B2B containment.",
    )

    release = sub.add_parser("release", parents=[common], help="Reverse containment, concurrently.")
    release.add_argument("--host", help="Device hostname or MDE machine id.")
    release.add_argument("--user", help="User principal name or Entra object id.")
    release.add_argument(
        "--comment",
        default="DAIR containment loop - release",
        help="Comment recorded on the MDE machine action.",
    )
    release.add_argument(
        "--enable-account", action="store_true", help="Also set accountEnabled=true."
    )

    sub.add_parser(
        "preflight", parents=[common], help="Validate credentials and API reachability, then exit."
    )

    status = sub.add_parser(
        "status",
        parents=[common],
        help="Show whether containment has actually taken effect. Read-only.",
    )
    status.add_argument("--host", help="Device hostname or MDE machine id.")
    status.add_argument("--user", help="User principal name or Entra object id.")
    status.add_argument(
        "--wait",
        action="store_true",
        help="Poll until any in-flight isolate or release has taken effect, or --timeout.",
    )
    status.add_argument(
        "--timeout", type=int, default=600, help="Seconds to wait with --wait (default 600)."
    )
    status.add_argument(
        "--interval", type=int, default=10, help="Seconds between polls with --wait (default 10)."
    )

    return parser


# -- status ------------------------------------------------------------------

# Read-only commands change nothing, so they neither need the guardrail config
# nor write audit records.
READ_ONLY_COMMANDS = ("preflight", "status")


def _fmt_time(value: Optional[str]) -> str:
    parsed = parse_mde_time(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%SZ") if parsed else (value or "?")


def _describe_action(action: Dict[str, Any]) -> str:
    line = (
        f"{action.get('type', '?'):<9} {action.get('status', '?'):<10} "
        f"requested {_fmt_time(action.get('creationDateTimeUtc'))}"
    )
    duration = action_duration_s(action)
    if duration is not None:
        line += f", took {duration:.0f}s"
    if action.get("requestor"):
        line += f" by {action['requestor']}"
    return line


def _wait_until_settled(
    fetch: Callable[[], Tuple[IsolationState, List[Dict[str, Any]]]],
    timeout: int,
    interval: int,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Tuple[IsolationState, List[Dict[str, Any]]]:
    """Poll until no isolate/release is in flight, or the timeout passes."""
    deadline = clock() + timeout
    state, actions = fetch()
    last_label = None
    while True:
        if state.label != last_label:
            LOG.info("Status: %s", state.label)
            last_label = state.label
        if state.settled or clock() >= deadline:
            return state, actions
        sleep(max(0.0, min(interval, deadline - clock())))
        state, actions = fetch()


def _run_status(args: argparse.Namespace, tokens: TokenProvider) -> int:
    code = EXIT_OK
    report: Dict[str, Any] = {}
    lines: List[str] = []

    if args.host:
        mde = DefenderClient(tokens)
        try:
            machine = mde.resolve_machine(args.host)

            def fetch() -> Tuple[IsolationState, List[Dict[str, Any]]]:
                actions = mde.isolation_actions(machine["id"])
                return isolation_state(actions), actions

            if args.wait:
                state, actions = _wait_until_settled(fetch, args.timeout, args.interval)
            else:
                state, actions = fetch()
        except ApiError as exc:
            LOG.error("%s", exc)
            return EXIT_ACTION_FAILED

        name = machine.get("computerDnsName") or args.host
        lines.append(f"{name}  (machine {machine['id']})")
        lines.append(f"  State   : {state.label}")
        if actions:
            lines.append("  History :")
            lines.extend(f"    {_describe_action(a)}" for a in actions[:5])
        else:
            lines.append("  History : no isolate or release actions on record")

        if state.last_failed:
            code = EXIT_ACTION_FAILED
        if args.wait and not state.settled:
            lines.append(
                f"  Timed out after {args.timeout}s -- the {state.pending} has not taken effect."
            )
            code = EXIT_ACTION_FAILED

        report["host"] = {
            "machine_id": machine["id"],
            "name": name,
            "state": state.label,
            "isolated": state.isolated,
            "pending": state.pending,
            "settled": state.settled,
            "history": actions[:5],
        }

    if args.user:
        try:
            user = EntraClient(tokens).resolve_user(args.user)
        except ApiError as exc:
            LOG.error("%s", exc)
            return EXIT_ACTION_FAILED

        upn = user.get("userPrincipalName") or args.user
        lines.append(f"{upn}  (user {user.get('id')})")
        lines.append(f"  Enabled             : {user.get('accountEnabled')}")
        lines.append(f"  Type                : {user.get('userType')}")
        lines.append(
            "  Sessions valid from : "
            f"{_fmt_time(user.get('signInSessionsValidFromDateTime'))}"
            "  (tokens issued before this are revoked)"
        )
        report["user"] = {
            "object_id": user.get("id"),
            "upn": upn,
            "account_enabled": user.get("accountEnabled"),
            "user_type": user.get("userType"),
            "sessions_valid_from": user.get("signInSessionsValidFromDateTime"),
        }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print("\n" + "\n".join(lines) + "\n")
    return code


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(args.verbose)

    if not args.json:
        print(BANNER, file=sys.stderr)

    # Order matters: the cheapest, most safety-critical, purely local checks run
    # first. Constructing the auth client performs network I/O, and a guardrail
    # that only gets evaluated after the network is reachable is not a guardrail.
    guardrails = {"protected_users": [], "protected_devices": []}
    if args.command != "preflight" and not args.host and not args.user:
        LOG.error("Specify --host, --user, or both.")
        return EXIT_USAGE

    if args.command not in READ_ONLY_COMMANDS:
        try:
            guardrails = _load_guardrails(args.config)
        except ConfigError as exc:
            LOG.error("CONFIG: %s", exc)
            return EXIT_USAGE

        if not args.no_guardrail:
            try:
                validate_guardrails(guardrails["protected_users"], guardrails["protected_devices"])
                if args.command == "contain":
                    # Refuse protected targets from what was typed, before any
                    # API -- or even the token endpoint -- is contacted.
                    check_targets(
                        args.host,
                        args.user,
                        guardrails["protected_users"],
                        guardrails["protected_devices"],
                    )
            except GuardrailNotConfigured as exc:
                LOG.error("GUARDRAIL: %s", exc)
                return EXIT_GUARDRAIL
            except ProtectedPrincipalError as exc:
                LOG.error("GUARDRAIL: %s", exc)
                return EXIT_GUARDRAIL
        else:
            LOG.warning(
                "Protected-principal guardrail DISABLED via --no-guardrail. "
                "Break-glass accounts are not protected in this run."
            )

    try:
        credentials = AppCredentials.from_env()
        tokens = TokenProvider(credentials)
    except AuthError as exc:
        LOG.error("%s", exc)
        return EXIT_AUTH
    except Exception as exc:  # noqa: BLE001 - MSAL raises transport errors here
        LOG.error(
            "Could not initialise authentication against tenant %s: %s: %s",
            os.environ.get("DAIR_TENANT_ID", "<unset>"),
            exc.__class__.__name__,
            exc,
        )
        LOG.error("Check network egress to login.microsoftonline.com and the tenant id.")
        return EXIT_AUTH

    if args.command == "preflight":
        try:
            tokens.preflight()
        except AuthError as exc:
            LOG.error("Preflight FAILED: %s", exc)
            return EXIT_AUTH
        LOG.info(
            "Preflight OK. Tokens issued for Graph and Defender for Endpoint, "
            "each carrying the application roles containment requires."
        )
        return EXIT_OK

    if args.command == "status":
        return _run_status(args, tokens)

    loop = ContainmentLoop(
        defender=DefenderClient(tokens),
        entra=EntraClient(tokens),
        audit=AuditLog(args.audit_log),
        protected_users=guardrails["protected_users"],
        protected_devices=guardrails["protected_devices"],
        require_guardrail=False,  # already validated above, before any network I/O
    )

    if args.execute and not args.yes:
        targets = ", ".join(filter(None, [args.host, args.user]))
        verb = "CONTAIN" if args.command == "contain" else "RELEASE"
        refusal = _confirm(f"\n{verb} {targets} -- this will take effect immediately.")
        if refusal:
            # Say why, so an operator never mistakes a mistyped confirmation
            # for some other failure. Nothing has been changed at this point.
            LOG.warning("Aborted: %s. Nothing was changed.", refusal)
            return EXIT_ABORTED

    try:
        if args.command == "contain":
            result = loop.contain(
                host=args.host,
                user=args.user,
                comment=args.comment,
                isolation_type=args.isolation_type,
                disable_account=args.disable_account,
                execute=args.execute,
            )
        else:
            result = loop.release(
                host=args.host,
                user=args.user,
                comment=args.comment,
                enable_account=args.enable_account,
                execute=args.execute,
            )
    except ProtectedPrincipalError as exc:
        # Raised when a target was refused after resolution -- an object id or
        # machine id that turned out to be protected. Nothing was changed.
        LOG.error("GUARDRAIL: %s", exc)
        return EXIT_GUARDRAIL
    except Exception as exc:  # noqa: BLE001 - surface anything unexpected clearly
        LOG.exception("Containment loop failed: %s", exc)
        return EXIT_ACTION_FAILED

    if args.json:
        print(
            json.dumps(
                {
                    "mode": result.mode,
                    "ok": result.ok,
                    "wall_clock_ms": result.wall_clock_ms,
                    "sequential_ms": result.serial_ms,
                    "actions": [vars(r) for r in result.results],
                },
                indent=2,
                default=str,
            )
        )
    else:
        print("\n" + result.report() + "\n")
        if result.mode == "dry-run":
            if result.ok:
                print("DRY RUN -- nothing was changed. Re-run with --execute to act.\n")
            else:
                # Never invite --execute over a failure: containment only acts
                # when every target resolves, so it would change nothing anyway.
                print(
                    "DRY RUN -- nothing was changed. Resolve the failure above before "
                    "using --execute; as things stand it would not act on anything.\n"
                )

    return EXIT_OK if result.ok else EXIT_ACTION_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
