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
from typing import Any, Dict, List, Optional

from .auth import MDE_RESOURCE, TokenProvider
from .client import ApiError, BaseApiClient

LOG = logging.getLogger(__name__)

MDE_BASE_URL = "https://api.securitycenter.microsoft.com/api"

ISOLATION_TYPES = ("full", "selective")


class MachineNotFound(ApiError):
    """No device in MDE matched the supplied identifier."""


class DefenderClient(BaseApiClient):
    def __init__(self, token_provider: TokenProvider, **kwargs) -> None:
        super().__init__(token_provider, MDE_RESOURCE, MDE_BASE_URL, **kwargs)

    # -- lookup ------------------------------------------------------------

    def resolve_machine(self, identifier: str) -> Dict[str, Any]:
        """Resolve a machine id or hostname to a device record.

        Accepts either an MDE machine id or a DNS name. Hostname lookup can be
        ambiguous -- a rebuilt or re-imaged host may appear multiple times -- so
        this returns the most recently seen active device and logs the collision.
        """
        # Try direct id lookup first; MDE machine ids are 40-char hex strings.
        if len(identifier) == 40 and all(c in "0123456789abcdef" for c in identifier.lower()):
            try:
                return self.get(f"/machines/{identifier}")
            except ApiError as exc:
                if exc.status_code != 404:
                    raise
                LOG.debug("No machine with id %s; falling back to hostname search", identifier)

        name = identifier.split(".")[0].lower()
        result = self.get(
            "/machines",
            params={"$filter": f"startswith(computerDnsName,'{name}')"},
        )
        machines: List[Dict[str, Any]] = (result or {}).get("value", [])

        if not machines:
            raise MachineNotFound(f"No MDE device matched '{identifier}'", status_code=404)

        exact = [m for m in machines if (m.get("computerDnsName") or "").split(".")[0].lower() == name]
        candidates = exact or machines

        if len(candidates) > 1:
            LOG.warning(
                "%d devices matched '%s' (ids: %s). Selecting most recently seen. "
                "Confirm the correct device before relying on this in a live incident.",
                len(candidates), identifier, ", ".join(m.get("id", "?") for m in candidates[:5]),
            )

        candidates.sort(key=lambda m: m.get("lastSeen") or "", reverse=True)
        chosen = candidates[0]
        LOG.info(
            "Resolved '%s' -> machine %s (%s, health=%s, lastSeen=%s)",
            identifier, chosen.get("id"), chosen.get("computerDnsName"),
            chosen.get("healthStatus"), chosen.get("lastSeen"),
        )
        return chosen

    # -- actions -----------------------------------------------------------

    def isolate(
        self,
        machine_id: str,
        comment: str,
        isolation_type: str = "full",
    ) -> Dict[str, Any]:
        """Isolate a device. Returns the machine action record."""
        if isolation_type not in ISOLATION_TYPES:
            raise ValueError(f"isolation_type must be one of {ISOLATION_TYPES}, got {isolation_type!r}")

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
