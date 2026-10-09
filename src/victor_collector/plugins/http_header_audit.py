"""Response security header audit.

`analyze_headers` is pure (no I/O) so it's testable against a constructed
`httpx.Headers` object, same split-execution-from-logic pattern as the
other plugins.
"""

from __future__ import annotations

import httpx

from victor_collector.models import RawObservation, Target
from victor_collector.plugins import PluginConfig, register

DEFAULT_TIMEOUT_SECONDS = 15

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def analyze_headers(headers: httpx.Headers, url: str) -> dict:
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    return {"url": url, "present_headers": present, "missing_headers": missing}


def _normalize_url(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else f"https://{target}"


class HttpHeaderAuditPlugin:
    name = "http-header-audit"
    safe_mode = True
    requires_credentials = False

    def run(self, target: Target, config: PluginConfig) -> list[RawObservation]:
        url = _normalize_url(target.value)
        timeout = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        response = httpx.get(url, timeout=timeout, follow_redirects=config.get("follow_redirects", True), verify=False)
        raw = analyze_headers(response.headers, str(response.url))
        raw["status_code"] = response.status_code
        return [RawObservation(plugin=self.name, target=str(response.url), raw=raw)]


register(HttpHeaderAuditPlugin())
