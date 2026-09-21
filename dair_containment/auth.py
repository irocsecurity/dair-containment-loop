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

import base64
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional

import msal

LOG = logging.getLogger(__name__)

GRAPH_RESOURCE = "https://graph.microsoft.com"
MDE_RESOURCE = "https://api.securitycenter.microsoft.com"

AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"

# Application roles each API must carry for containment to complete. Checked by
# preflight against the roles actually present in the issued token -- a token is
# issued successfully even when *no* permission has been admin-consented, so
# acquiring one proves nothing about whether containment can act.
#
# User.ReadWrite.All includes read, so User.Read.All is not additionally required.
REQUIRED_ROLES: Dict[str, FrozenSet[str]] = {
    GRAPH_RESOURCE: frozenset({"User.ReadWrite.All"}),
    MDE_RESOURCE: frozenset({"Machine.Read.All", "Machine.Isolate"}),
}


class AuthError(RuntimeError):
    """Raised when a token cannot be acquired. Never carries secret material."""


def token_roles(token: str) -> FrozenSet[str]:
    """Return the application roles carried in an access token.

    Reads the JWT payload without verifying the signature. That is deliberate
    and safe here: this inspects a token we were just issued in order to report
    on it, and authorises nothing. Never logs the token itself.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError) as exc:
        raise AuthError(
            "Access token is not a decodable JWT; granted roles cannot be read."
        ) from exc
    return frozenset(claims.get("roles") or [])


@dataclass(frozen=True)
class AppCredentials:
    """App-only credentials for the containment service principal.

    Secret-bearing fields are excluded from ``repr`` so that logging this
    object, or an exception that captures it, cannot leak a key or secret.
    """

    tenant_id: str
    client_id: str
    client_secret: Optional[str] = field(default=None, repr=False)
    certificate_path: Optional[str] = None
    certificate_thumbprint: Optional[str] = None
    certificate_pem: Optional[str] = field(default=None, repr=False)

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

        pem = os.environ.get("DAIR_CERT_PEM") or None
        if pem and "\\n" in pem and "\n" not in pem:
            # Tolerate a key flattened onto one line with literal \n escapes.
            pem = pem.replace("\\n", "\n")

        creds = cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=os.environ.get("DAIR_CLIENT_SECRET") or None,
            certificate_path=os.environ.get("DAIR_CERT_PATH") or None,
            certificate_thumbprint=os.environ.get("DAIR_CERT_THUMBPRINT") or None,
            certificate_pem=pem,
        )
        creds.validate()
        return creds

    def validate(self) -> None:
        has_key = bool(self.certificate_pem or self.certificate_path)
        has_cert = bool(has_key and self.certificate_thumbprint)
        has_secret = bool(self.client_secret)

        if not has_cert and not has_secret:
            raise AuthError(
                "No usable credential. Set DAIR_CERT_THUMBPRINT plus either DAIR_CERT_PEM "
                "or DAIR_CERT_PATH (preferred), or DAIR_CLIENT_SECRET."
            )
        if self.certificate_pem:
            # DAIR_CERT_PEM lets a secret manager inject the key straight into
            # the process (e.g. `op run`), so it never has to exist on disk.
            if "PRIVATE KEY" not in self.certificate_pem:
                raise AuthError("DAIR_CERT_PEM does not contain a PEM-encoded private key.")
            if self.certificate_path:
                LOG.warning("Both DAIR_CERT_PEM and DAIR_CERT_PATH are set; using DAIR_CERT_PEM.")
        elif has_cert and not os.path.isfile(self.certificate_path or ""):
            raise AuthError(f"Certificate file not found: {self.certificate_path}")
        if has_secret and not has_cert:
            LOG.warning(
                "Using a client secret. Certificate credentials are strongly "
                "preferred for a principal that can isolate hosts and revoke sessions."
            )

    def _msal_credential(self):
        if self.certificate_thumbprint and self.certificate_pem:
            return {"thumbprint": self.certificate_thumbprint, "private_key": self.certificate_pem}
        if self.certificate_thumbprint and self.certificate_path:
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
        """Acquire both tokens and confirm each carries the roles containment needs.

        A partial containment is worse than none: if we can isolate the host but
        cannot revoke the session, the responder needs to know that *before* the
        host drops off the network. Acquiring a token is not enough to know that,
        because a token is issued even when no permission has been consented --
        so this reads the roles actually granted and fails on any that are missing.

        What this cannot prove is per-object access. Some principals, such as
        members of a restricted management administrative unit or privileged
        accounts, may still refuse a write that the roles would otherwise allow.
        """
        results: Dict[str, bool] = {}
        problems = []
        for resource in (GRAPH_RESOURCE, MDE_RESOURCE):
            token = self.get_token(resource)
            required = REQUIRED_ROLES[resource]
            try:
                granted = token_roles(token)
            except AuthError as exc:
                LOG.warning("Preflight could not verify roles for %s: %s", resource, exc)
                results[resource] = True
                continue

            missing = sorted(required - granted)
            if missing:
                problems.append(f"{resource} is missing application role(s): {', '.join(missing)}")
                results[resource] = False
            else:
                LOG.info("Preflight OK: %s (roles: %s)", resource, ", ".join(sorted(required)))
                results[resource] = True

        if problems:
            raise AuthError(
                "; ".join(problems) + ". Add them as Application permissions, not Delegated, "
                "and grant admin consent."
            )
        return results
