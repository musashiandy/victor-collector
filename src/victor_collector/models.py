"""Data shapes shared across plugins, storage, and the sync client.

Mirrors docs/collector-design.md §6 in the victor-recon-console repo —
keep these two in sync if either changes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["Info", "Low", "Medium", "High", "Critical"]


class Target(BaseModel):
    """A host, IP, CIDR, or URL a plugin runs against."""

    value: str
    scope: str = "Unassigned"


class RawObservation(BaseModel):
    """Structured plugin output. Never a Finding — see §6 for why."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin: str
    target: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw: dict[str, Any]
    redacted: bool = False


class CollectorCredentials(BaseModel):
    """Stored at ~/.victor/credentials.json (mode 0600) after `victor
    enroll` succeeds — docs/collector-design.md §7.1. Never logged,
    never included in evidence bundles.
    """

    control_plane: str
    collector_id: str
    credential: str
    account_id: str
    hostname: str
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SSHCredentialRef(BaseModel):
    """A named SSH credential for `package-baseline-diff`, stored at
    ~/.victor/credentials/<name>.json (mode 0600) — see
    docs/collector-design.md §15 for why this is a plain, operator-
    populated file rather than an OS keyring integration. The collector
    only ever reads this; it never generates or manages secret material
    for a target host itself.
    """

    username: str
    auth_method: Literal["key", "password"]
    key_path: str | None = None
    key_passphrase: str | None = None
    password: str | None = None


class Finding(BaseModel):
    """Basic local-triage output (Standalone Mode, §9). Same shape the
    web app expects per docs/backend-integration.md, minus the fields
    (owner, reviewed, report) that only make sense once a real backend
    and UI are managing it.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    asset: str
    evidence: str
    remediation: str
    tags: list[str] = Field(default_factory=list)
    source_observation_id: str
