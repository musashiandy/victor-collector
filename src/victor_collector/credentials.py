"""Local credential storage for the cloud-connected path
(docs/collector-design.md §7.1). Written once by `victor enroll`, read
by `victor run`'s heartbeat/poll loop.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from victor_collector.models import CollectorCredentials

CREDENTIALS_PATH = Path.home() / ".victor" / "credentials.json"


def save(creds: CollectorCredentials) -> None:
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_PATH.write_text(creds.model_dump_json(indent=2), encoding="utf-8")
    # Best-effort on Windows — no real POSIX mode bits there; the actual
    # protection on that platform is the OS-level ACL on the user's
    # profile directory, not this call.
    os.chmod(CREDENTIALS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def load() -> CollectorCredentials | None:
    if not CREDENTIALS_PATH.exists():
        return None
    return CollectorCredentials.model_validate_json(CREDENTIALS_PATH.read_text(encoding="utf-8"))
