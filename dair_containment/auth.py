# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Token acquisition for the two APIs the containment loop touches.

The DAIR Containment Loop acts against two independent Microsoft APIs that do
*not* share an audience:

    Microsoft Graph              https://graph.microsoft.com
    Defender for Endpoint (MDE)  https://api.securitycenter.microsoft.com

Each needs its own access token. This module wraps a single MSAL confidential
client application and hands out per-resource tokens, relying on MSAL's own
in-memory cache so repeated calls inside one run do not re-hit the IdP.

Authentication is app-only (client credentials). Certificate credentials are
strongly preferred over client secrets for a tool that can isolate hosts and
revoke sessions -- see SECURITY.md.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from typing import Dict, Optional

import msal

LOG = logging.getLogger(__name__)

GRAPH_RESOURCE = "https://graph.microsoft.com"
MDE_RESOURCE = "https://api.securitycenter.microsoft.com"

AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"


class AuthError(RuntimeError):
    """Raised when a token cannot be acquired. Never carries secret material."""


@dataclass(frozen=True)
class AppCredentials:
    """App-only credentials for the containment service principal."""

    tenant_id: str
    client_id: str
    client_secret: Optional[str] = None
    certificate_path: Optional[str] = None
    certificate_thumbprint: Optional[str] = None

    @classmethod
    def from_env(cls) -> AppCredentials:
        """Build credentials from environment. See .env.example."""
        tenant_id = os.environ.get("DAIR_TENANT_ID", "").strip()
        client_id = os.environ.get("DAIR_CLIENT_ID", "").strip()

        missing = [
            name
            for name, value in (("DAIR_TENANT_ID", tenant_id), ("DAIR_CLIENT_ID", client_id))
            if not value
        ]
        if missing:
            raise AuthError(f"Missing required environment variables: {', '.join(missing)}")

        creds = cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=os.environ.get("DAIR_CLIENT_SECRET") or None,
            certificate_path=os.environ.get("DAIR_CERT_PATH") or None,
            certificate_thumbprint=os.environ.get("DAIR_CERT_THUMBPRINT") or None,
        )
        creds.validate()
        return creds

    def validate(self) -> None:
        has_cert = bool(self.certificate_path and self.certificate_thumbprint)
        has_secret = bool(self.client_secret)

        if not has_cert and not has_secret:
            raise AuthError(
                "No usable credential. Set DAIR_CERT_PATH + DAIR_CERT_THUMBPRINT "
                "(preferred) or DAIR_CLIENT_SECRET."
            )
        if has_cert and not os.path.isfile(self.certificate_path or ""):
            raise AuthError(f"Certificate file not found: {self.certificate_path}")
        if has_secret and not has_cert:
            LOG.warning(
                "Using a client secret. Certificate credentials are strongly "
                "preferred for a principal that can isolate hosts and revoke sessions."
            )

    def _msal_credential(self):
        if self.certificate_path and self.certificate_thumbprint:
            with open(self.certificate_path, encoding="utf-8") as handle:
                private_key = handle.read()
            return {"thumbprint": self.certificate_thumbprint, "private_key": private_key}
        return self.client_secret


class TokenProvider:
    """Thread-safe, per-resource token vendor backed by one MSAL app.

    Both halves of the containment loop run concurrently, so ``get_token`` is
    called from multiple threads. MSAL's cache is thread-safe for reads, but we
    serialise acquisition to avoid a thundering herd on first call.
    """

    def __init__(self, credentials: AppCredentials) -> None:
        self._credentials = credentials
        self._lock = threading.Lock()
        self._app = msal.ConfidentialClientApplication(
            client_id=credentials.client_id,
            authority=AUTHORITY_TEMPLATE.format(tenant_id=credentials.tenant_id),
            client_credential=credentials._msal_credential(),
        )

    def get_token(self, resource: str) -> str:
        """Return a bearer token for ``resource`` (e.g. GRAPH_RESOURCE)."""
        scope = f"{resource.rstrip('/')}/.default"
        with self._lock:
            result: Dict = self._app.acquire_token_for_client(scopes=[scope])

        if "access_token" in result:
            LOG.debug("Acquired token for %s (expires_in=%ss)", resource, result.get("expires_in"))
            return result["access_token"]

        # MSAL error payloads carry no token material, but be explicit about
        # what we surface so a secret can never land in a log line.
        raise AuthError(
            "Token acquisition failed for {resource}: {error} -- {desc} "
            "(correlation_id={cid})".format(
                resource=resource,
                error=result.get("error", "unknown_error"),
                desc=result.get("error_description", "no description returned"),
                cid=result.get("correlation_id", "n/a"),
            )
        )

    def preflight(self) -> Dict[str, bool]:
        """Acquire both tokens up front so auth failures surface before we act.

        Returns a map of resource -> success. Raises AuthError on the first
        failure, because a partial containment is worse than none: if we can
        isolate the host but cannot revoke the session, the responder needs to
        know that *before* the host drops off the network.
        """
        results: Dict[str, bool] = {}
        for resource in (GRAPH_RESOURCE, MDE_RESOURCE):
            self.get_token(resource)
            results[resource] = True
            LOG.info("Preflight OK: %s", resource)
        return results
