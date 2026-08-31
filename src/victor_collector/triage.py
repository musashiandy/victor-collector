"""Basic local triage (docs/collector-design.md §9).

Deliberately the simple version: one observation in, one Finding out, no
cross-session correlation, no attack-chain narrative. That deeper analysis
is cloud-side, paid-tier work — see the "open/closed line" note in §9.
"""

from __future__ import annotations

import json

import httpx
import structlog

from victor_collector.models import Finding, RawObservation

log = structlog.get_logger()

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1"

_PROMPT_TEMPLATE = """You are a security analyst triaging a single raw recon \
observation. Respond with ONLY a JSON object (no markdown, no commentary) \
matching this exact shape:

{{"title": "...", "severity": "Info|Low|Medium|High|Critical", \
"confidence": 0-100, "remediation": "..."}}

Observation from plugin "{plugin}" against target "{target}":
{raw}
"""


def triage_observation(
    observation: RawObservation,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    timeout: float = 60.0,
) -> Finding:
    """Calls a local Ollama model to classify one observation.

    Raises httpx.HTTPError if Ollama isn't reachable — callers decide
    whether that's fatal (CLI) or something to retry/report (future
    daemon mode).
    """
    prompt = _PROMPT_TEMPLATE.format(
        plugin=observation.plugin,
        target=observation.target,
        raw=json.dumps(observation.raw),
    )

    response = httpx.post(
        f"{ollama_url}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
        timeout=timeout,
    )
    response.raise_for_status()
    parsed = json.loads(response.json()["response"])

    return Finding(
        title=parsed["title"],
        severity=parsed["severity"],
        confidence=int(parsed["confidence"]),
        asset=observation.target,
        evidence=json.dumps(observation.raw),
        remediation=parsed["remediation"],
        tags=[observation.plugin],
        source_observation_id=observation.id,
    )
