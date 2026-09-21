# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Microsoft Defender for Endpoint -- device isolation and release.

Required application permissions on the containment service principal:

    Machine.Read.All      resolve a hostname to a machine id, poll action status
    Machine.Isolate       isolate and release devices

Isolation types:

    full        Device is cut off from the network entirely.
    selective   Device retains Outlook, Teams, and Skype for Business
                connectivity so the user can be reached. Lower blast radius;
                prefer it when the responder needs to talk to the user, or when
                business impact of a full cut is not yet justified.

Both isolate and release are *reversible* actions under the DAIR reversibility
test, which is precisely why they are appropriate for immediate, pre-delegated
execution rather than an approval queue.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from .auth import MDE_RESOURCE, TokenProvider
from .client import ApiError, BaseApiClient

LOG = logging.getLogger(__name__)

MDE_BASE_URL = "https://api.securitycenter.microsoft.com/api"

ISOLATION_TYPES = ("full", "selective")

# Characters a device name may contain. Anything else -- a quote, parenthesis,
# comma or space -- could alter the OData filter the name is placed into. That
# matters once hostnames arrive from alert data in a SOAR integration, where an
# attacker can influence them and could steer isolation onto a different device.
_DEVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

_MACHINE_ID = re.compile(r"^[0-9a-f]{40}$")


class MachineNotFound(ApiError):
    """No device in MDE matched the supplied identifier."""


class DefenderClient(BaseApiClient):
    def __init__(self, token_provider: TokenProvider, **kwargs) -> None:
        super().__init__(token_provider, MDE_RESOURCE, MDE_BASE_URL, **kwargs)

    # -- lookup ------------------------------------------------------------

    def resolve_machine(self, identifier: str) -> Dict[str, Any]:
        """Resolve a machine id or device name to exactly one device record.

        Accepts an MDE machine id, a short hostname, or an FQDN. A name must
        match *exactly*: a typo or truncation fails rather than resolving to
        whichever device happens to share its prefix. On a tool that isolates
        machines, "close enough" is how the wrong one goes offline.

        A rebuilt or re-imaged host may legitimately appear several times under
        the same name; in that case the most recently seen record is chosen and
        the collision is logged.
        """
        identifier = identifier.strip()

        # Direct id lookup first; MDE machine ids are 40-char hex strings.
        if _MACHINE_ID.match(identifier.lower()):
            try:
                machine = self.get(f"/machines/{identifier.lower()}")
                self._log_resolved(identifier, machine)
                return machine
            except ApiError as exc:
                if exc.status_code != 404:
                    raise
                LOG.debug("No machine with id %s; falling back to name search", identifier)

        if not _DEVICE_NAME.match(identifier):
            raise MachineNotFound(
                f"'{identifier}' is not a valid device name or machine id.", status_code=400
            )

        wanted_fqdn = identifier.lower()
        wanted_short = wanted_fqdn.split(".", 1)[0]

        # Server-side filter narrows by prefix so FQDN records are found from a
        # short name. The match itself is decided exactly, below -- never by prefix.
        result = self.get(
            "/machines",
            params={"$filter": f"startswith(computerDnsName,'{wanted_short}')"},
        )
        machines: List[Dict[str, Any]] = (result or {}).get("value", [])

        def dns(m: Dict[str, Any]) -> str:
            return (m.get("computerDnsName") or "").lower()

        if "." in wanted_fqdn:
            candidates = [m for m in machines if dns(m) == wanted_fqdn]
        else:
            candidates = [m for m in machines if dns(m).split(".", 1)[0] == wanted_short]

        if not candidates:
            near = sorted({dns(m) for m in machines if dns(m)})[:5]
            hint = f" Similar names: {', '.join(near)}." if near else ""
            raise MachineNotFound(
                f"No MDE device is named exactly '{identifier}'.{hint} "
                "Use the full device name or the machine id.",
                status_code=404,
            )

        if len(candidates) > 1:
            LOG.warning(
                "%d devices are named '%s' (ids: %s). Selecting the most recently seen. "
                "Confirm the correct device before relying on this in a live incident.",
                len(candidates),
                identifier,
                ", ".join(m.get("id", "?") for m in candidates[:5]),
            )

        candidates.sort(key=lambda m: m.get("lastSeen") or "", reverse=True)
        chosen = candidates[0]
        self._log_resolved(identifier, chosen)
        return chosen

    @staticmethod
    def _log_resolved(identifier: str, machine: Dict[str, Any]) -> None:
        # Logged on every resolution path, including direct machine-id lookup,
        # so an operator always sees which device an identifier became.
        LOG.info(
            "Resolved '%s' -> machine %s (%s, health=%s, lastSeen=%s)",
            identifier,
            machine.get("id"),
            machine.get("computerDnsName"),
            machine.get("healthStatus"),
            machine.get("lastSeen"),
        )

    # -- actions -----------------------------------------------------------

    def isolate(
        self,
        machine_id: str,
        comment: str,
        isolation_type: str = "full",
    ) -> Dict[str, Any]:
        """Isolate a device. Returns the machine action record."""
        if isolation_type not in ISOLATION_TYPES:
            raise ValueError(
                f"isolation_type must be one of {ISOLATION_TYPES}, got {isolation_type!r}"
            )

        LOG.info("Isolating machine %s (type=%s)", machine_id, isolation_type)
        return self.post(
            f"/machines/{machine_id}/isolate",
            json_body={"Comment": comment, "IsolationType": isolation_type.capitalize()},
        )

    def release(self, machine_id: str, comment: str) -> Dict[str, Any]:
        """Release a device from isolation. This is the undo for ``isolate``."""
        LOG.info("Releasing machine %s from isolation", machine_id)
        return self.post(
            f"/machines/{machine_id}/unisolate",
            json_body={"Comment": comment},
        )

    def get_action(self, action_id: str) -> Dict[str, Any]:
        """Poll a machine action. Status is one of Pending/InProgress/Succeeded/Failed/Cancelled."""
        return self.get(f"/machineactions/{action_id}")

    def active_isolation(self, machine_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recent isolation action for a machine, if any.

        Used to avoid issuing a duplicate isolate against a device that is
        already contained -- a common source of confusing action history during
        a multi-responder incident.
        """
        result = self.get(
            "/machineactions",
            params={
                "$filter": f"machineId eq '{machine_id}' and type eq 'Isolate'",
                "$top": "1",
                "$orderby": "creationDateTimeUtc desc",
            },
        )
        actions = (result or {}).get("value", [])
        return actions[0] if actions else None
