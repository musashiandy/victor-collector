"""Privacy Mode redaction (docs/collector-design.md §8) — on by
default on the cloud path. Replaces hostnames/IPs in an observation's
raw payload with stable, session-scoped pseudonyms before upload. The
real-value <-> pseudonym mapping lives only in a local SQLite file
(~/.victor/redaction-map.db), never uploaded — reversal only ever
happens on this machine.

A stable pseudonym (not just stripping the value) matters because
cloud-side AI triage still needs to know two findings reference the
same asset to build attack-chain narratives — see §8's reasoning.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from victor_collector.models import RawObservation

DEFAULT_DB_PATH = Path.home() / ".victor" / "redaction-map.db"

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_salts (
    session_id TEXT PRIMARY KEY,
    salt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pseudonyms (
    session_id TEXT NOT NULL,
    real_value TEXT NOT NULL,
    kind TEXT NOT NULL,
    pseudonym TEXT NOT NULL,
    PRIMARY KEY (session_id, real_value)
);
"""


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def _salt_for_session(conn: sqlite3.Connection, session_id: str) -> str:
    row = conn.execute(
        "SELECT salt FROM session_salts WHERE session_id = ?", (session_id,)
    ).fetchone()
    if row:
        return row[0]
    salt = secrets.token_hex(16)
    conn.execute("INSERT INTO session_salts (session_id, salt) VALUES (?, ?)", (session_id, salt))
    return salt


def _pseudonym_for(conn: sqlite3.Connection, session_id: str, real_value: str, kind: str) -> str:
    row = conn.execute(
        "SELECT pseudonym FROM pseudonyms WHERE session_id = ? AND real_value = ?",
        (session_id, real_value),
    ).fetchone()
    if row:
        return row[0]

    salt = _salt_for_session(conn, session_id)
    digest = hashlib.sha256(f"{salt}:{real_value}".encode()).hexdigest()[:4]
    pseudonym = f"{kind}-{digest}"
    conn.execute(
        "INSERT INTO pseudonyms (session_id, real_value, kind, pseudonym) VALUES (?, ?, ?, ?)",
        (session_id, real_value, kind, pseudonym),
    )
    return pseudonym


def _redact_string(conn: sqlite3.Connection, session_id: str, value: str, target: str, target_pseudonym: str) -> str:
    """Replace every IPv4 substring, plus any exact occurrence of the
    known target value, with its stable pseudonym. The exact-match pass
    is what catches a hostname target (the IPv4 regex only ever catches
    IP-shaped substrings, so a hostname needs this separately).
    """
    result = value.replace(target, target_pseudonym) if target and target in value else value

    def _sub(match: re.Match[str]) -> str:
        return _pseudonym_for(conn, session_id, match.group(0), "IP")

    return _IPV4_RE.sub(_sub, result)


def _redact_value(conn: sqlite3.Connection, session_id: str, value: Any, target: str, target_pseudonym: str) -> Any:
    if isinstance(value, str):
        return _redact_string(conn, session_id, value, target, target_pseudonym)
    if isinstance(value, dict):
        return {k: _redact_value(conn, session_id, v, target, target_pseudonym) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(conn, session_id, v, target, target_pseudonym) for v in value]
    return value


def redact_observation(
    observation: RawObservation, *, session_id: str, db_path: Path = DEFAULT_DB_PATH
) -> RawObservation:
    """Returns a new RawObservation with hostnames/IPs in `target` and
    `raw` replaced by stable per-session pseudonyms. The original is
    left untouched. `db_path` is a real parameter (not just a module
    constant to monkeypatch) specifically so tests can point it at a
    tmp_path without touching a real user's mapping file.
    """
    with _connect(db_path) as conn:
        target_kind = "IP" if _IPV4_RE.fullmatch(observation.target) else "HOST"
        target_pseudonym = _pseudonym_for(conn, session_id, observation.target, target_kind)
        redacted_raw = _redact_value(conn, session_id, observation.raw, observation.target, target_pseudonym)

    return observation.model_copy(
        update={"target": target_pseudonym, "raw": redacted_raw, "redacted": True}
    )
