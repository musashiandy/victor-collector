"""Local SQLite storage for Standalone Mode (docs/collector-design.md §9).

Cloud-connected mode doesn't use this for findings — it uploads
observations and the cloud persists them. This module exists so
`victor recon ...` and the future `victor ui` produce something durable
and browsable with zero cloud account required.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from victor_collector.models import Finding, RawObservation

DEFAULT_DB_PATH = Path.home() / ".victor" / "collector.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    plugin TEXT NOT NULL,
    target TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    raw TEXT NOT NULL,
    redacted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    asset TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    tags TEXT NOT NULL,
    source_observation_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS package_baselines (
    target TEXT PRIMARY KEY,
    packages TEXT NOT NULL,
    established_at TEXT NOT NULL
);
"""


@contextmanager
def connect(db_path: Path = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_observation(obs: RawObservation, db_path: Path = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO observations VALUES (?, ?, ?, ?, ?, ?)",
            (
                obs.id,
                obs.plugin,
                obs.target,
                obs.collected_at.isoformat(),
                json.dumps(obs.raw),
                int(obs.redacted),
            ),
        )


def save_finding(finding: Finding, db_path: Path = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                finding.title,
                finding.severity,
                finding.confidence,
                finding.asset,
                finding.evidence,
                finding.remediation,
                json.dumps(finding.tags),
                finding.source_observation_id,
            ),
        )


def get_package_baseline(target: str, db_path: Path = DEFAULT_DB_PATH) -> dict[str, str] | None:
    """The package-baseline-diff plugin's known-good reference for a
    target — established once on first run, never overwritten
    automatically (a rolling diff against the previous run would hide
    slow drift; see docs/collector-design.md §5)."""
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT packages FROM package_baselines WHERE target = ?", (target,)
        ).fetchone()
    return json.loads(row[0]) if row else None


def save_package_baseline(
    target: str, packages: dict[str, str], db_path: Path = DEFAULT_DB_PATH
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO package_baselines (target, packages, established_at) "
            "VALUES (?, ?, ?)",
            (target, json.dumps(packages), datetime.now(timezone.utc).isoformat()),
        )


def list_findings(db_path: Path = DEFAULT_DB_PATH) -> list[Finding]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM findings ORDER BY rowid DESC").fetchall()
    return [
        Finding(
            id=r[0],
            title=r[1],
            severity=r[2],
            confidence=r[3],
            asset=r[4],
            evidence=r[5],
            remediation=r[6],
            tags=json.loads(r[7]),
            source_observation_id=r[8],
        )
        for r in rows
    ]
