"""Operator-owned exact-target allowlist; cloud tasks cannot change this file."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, field_validator
from victor_collector.target_validation import validate_target

POLICY_PATH = Path.home() / ".victor" / "scope.json"


class PolicyError(Exception):
    pass


class Rule(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    expires_at: datetime
    plugins: list[str] = Field(min_length=1)

    @field_validator("target")
    @classmethod
    def single_target(cls, value: str) -> str:
        return validate_target(value)

    @field_validator("expires_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Expiry must include timezone, e.g. 2026-11-01T00:00:00Z")
        return value


def _load() -> list[Rule]:
    try:
        body = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if body.get("version") != 1:
            raise ValueError("Unsupported policy version")
        return [Rule.model_validate(rule) for rule in body["rules"]]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise PolicyError("Local authorization is missing or invalid. Run `victor authorize` on this collector.") from exc


def authorize(target: str, expires: str, plugins: list[str]) -> None:
    rule = Rule(target=target, expires_at=expires, plugins=plugins)
    if rule.expires_at <= datetime.now(timezone.utc):
        raise PolicyError("Authorization must expire in the future")
    rules = _load() if POLICY_PATH.exists() else []
    rules = [existing for existing in rules if existing.target != target] + [rule]
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = POLICY_PATH.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps({"version": 1, "rules": [item.model_dump(mode="json") for item in rules]}, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(POLICY_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def assert_allowed(target: str, plugin: str, *, now: datetime | None = None) -> None:
    if plugin != "http-header-audit" and "://" in target:
        raise PolicyError("TLS and service checks require a hostname or IP")
    instant = now or datetime.now(timezone.utc)
    for rule in _load():
        if rule.target == target and plugin in rule.plugins and rule.expires_at > instant:
            return
    raise PolicyError("Task refused by the collector's local target/plugin/expiry policy")
