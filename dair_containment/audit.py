# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Append-only JSONL audit trail.

Under DAIR, reversible containment actions are executed without prior approval.
That trade is only defensible if oversight moves to post-review -- which means
every action must leave a record that says what was done, by whom, to what, and
how to undo it.

Each record is one JSON object on one line. The file is opened in append mode
and flushed per write so a crash mid-incident does not lose the trail.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

LOG = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, path: str, run_id: Optional[str] = None) -> None:
        self.path = path
        self.run_id = run_id or f"dair-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        self._lock = threading.Lock()

        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)

        try:
            self._operator = getpass.getuser()
        except Exception:  # pragma: no cover - environment dependent
            self._operator = "unknown"
        self._host = socket.gethostname()

    def record(
        self,
        action: str,
        target: str,
        mode: str,
        result: str,
        *,
        reversible: bool,
        undo_hint: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write one audit record and return it."""
        entry = {
            "ts": _utc_now(),
            "run_id": self.run_id,
            "operator": self._operator,
            "operator_host": self._host,
            "action": action,
            "target": target,
            "mode": mode,
            "result": result,
            "reversible": reversible,
            "undo": undo_hint,
            "detail": detail or {},
        }

        line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
            except OSError as exc:
                # An audit failure must be loud, but must not abort containment
                # that is already in flight.
                LOG.error("AUDIT WRITE FAILED (%s): %s", exc, line)

        return entry
