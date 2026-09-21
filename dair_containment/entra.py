# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Microsoft Entra ID -- session revocation and account state.

Required application permissions on the containment service principal:

    User.Read.All          resolve and inspect the principal
    User.ReadWrite.All     revoke sessions, toggle accountEnabled

TOKEN MECHANICS -- read this before relying on revocation as containment.

``revokeSignInSessions`` stamps ``signInSessionsValidFromDateTime`` and
invalidates refresh tokens, session cookies, and Primary Refresh Tokens. It does
NOT immediately invalidate already-issued *access* tokens:

  * With Continuous Access Evaluation (CAE) enabled and the resource CAE-capable
    (Exchange Online, SharePoint, Teams, Graph), revocation propagates in
    roughly two minutes.
  * Without CAE, the adversary retains access for the remaining access-token
    lifetime -- up to 60-90 minutes.
  * If the adversary holds an app refresh token from an illicit OAuth consent
    grant, revocation does not help at all until that grant is removed.

A password reset alone is therefore never containment. This module implements
the identity half of the loop; the OAuth-grant half belongs to the eradication
loop and is deliberately out of scope for this tool.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from .auth import GRAPH_RESOURCE, TokenProvider
from .client import ApiError, BaseApiClient

LOG = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

USER_SELECT = (
    "id,userPrincipalName,displayName,accountEnabled,userType,"
    "onPremisesSyncEnabled,signInSessionsValidFromDateTime,mail"
)


class PrincipalNotFound(ApiError):
    """No Entra ID principal matched the supplied identifier."""


class EntraClient(BaseApiClient):
    def __init__(self, token_provider: TokenProvider, **kwargs) -> None:
        super().__init__(token_provider, GRAPH_RESOURCE, GRAPH_BASE_URL, **kwargs)

    # -- lookup ------------------------------------------------------------

    def resolve_user(self, identifier: str) -> Dict[str, Any]:
        """Resolve a UPN or object id to a user record, with containment caveats logged."""
        try:
            user = self.get(f"/users/{identifier}", params={"$select": USER_SELECT})
        except ApiError as exc:
            if exc.status_code == 404:
                raise PrincipalNotFound(
                    f"No Entra ID user matched '{identifier}'", status_code=404
                ) from exc
            raise

        # Mirrors the device-side resolution line. A dry run is the last point
        # at which an operator can notice they are about to act on the wrong
        # principal, so what the identifier resolved to must be visible.
        LOG.info(
            "Resolved '%s' -> user %s (%s, type=%s, enabled=%s, hybrid=%s)",
            identifier,
            user.get("id"),
            user.get("userPrincipalName"),
            user.get("userType"),
            user.get("accountEnabled"),
            bool(user.get("onPremisesSyncEnabled")),
        )

        if user.get("userType") == "Guest":
            LOG.warning(
                "%s is a GUEST (B2B) principal. Session revocation alone is NOT containment: "
                "the credential and session live in the home tenant, and the guest will "
                "re-authenticate via SSO within seconds. Disable the guest object "
                "(--disable-account) and notify the home tenant.",
                user.get("userPrincipalName"),
            )

        if user.get("onPremisesSyncEnabled"):
            LOG.warning(
                "%s is HYBRID-SYNCED. A cloud-side accountEnabled=false will be overwritten "
                "by the next directory sync. Disable in on-premises AD and force a delta sync.",
                user.get("userPrincipalName"),
            )

        return user

    # -- actions -----------------------------------------------------------

    def revoke_sessions(self, user_id: str) -> bool:
        """Revoke refresh tokens, session cookies, and PRTs for a principal."""
        LOG.info("Revoking sign-in sessions for %s", user_id)
        result = self.post(f"/users/{user_id}/revokeSignInSessions")
        # Graph returns {"value": true} on success; 204 yields None.
        return True if result is None else bool(result.get("value", True))

    def set_account_enabled(self, user_id: str, enabled: bool) -> None:
        """Enable or disable a principal. The undo for disable is enable."""
        LOG.info("Setting accountEnabled=%s for %s", enabled, user_id)
        self.patch(f"/users/{user_id}", json_body={"accountEnabled": enabled})

    def sessions_valid_from(self, user_id: str) -> str:
        """Read back the revocation watermark, for containment verification."""
        user = self.get(f"/users/{user_id}", params={"$select": "signInSessionsValidFromDateTime"})
        return user.get("signInSessionsValidFromDateTime", "")
