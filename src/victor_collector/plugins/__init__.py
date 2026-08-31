"""Recon plugin protocol and registry.

See docs/collector-design.md §5 in the victor-recon-console repo. Every
plugin declares `safe_mode` itself and the task loop enforces it — a
compromised or misconfigured control plane can't talk a plugin into
running something it didn't declare as safe.
"""

from __future__ import annotations

from typing import Protocol

from victor_collector.models import RawObservation, Target


class PluginConfig(dict):
    """Free-form per-plugin config, e.g. port ranges or credential refs."""


class ReconPlugin(Protocol):
    name: str
    safe_mode: bool
    requires_credentials: bool

    def run(self, target: Target, config: PluginConfig) -> list[RawObservation]: ...


_REGISTRY: dict[str, ReconPlugin] = {}


def register(plugin: ReconPlugin) -> ReconPlugin:
    _REGISTRY[plugin.name] = plugin
    return plugin


def get(name: str) -> ReconPlugin:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(
            f"Unknown plugin '{name}'. Available: {', '.join(sorted(_REGISTRY)) or '(none registered)'}"
        ) from None


def list_plugins() -> list[ReconPlugin]:
    return sorted(_REGISTRY.values(), key=lambda p: p.name)


# Importing here (rather than at package top) registers each plugin as a
# side effect of import, keeping this file the single source of truth for
# "what plugins exist" without a separate manual registration step.
from victor_collector.plugins import (  # noqa: E402,F401
    http_header_audit,
    service_inventory,
    tls_review,
)
