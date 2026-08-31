"""HTTP client for the cloud-connected path (docs/collector-design.md
§7). Talks to VICTOR Recon's cloud API — enroll, heartbeat, poll,
upload. Only `enroll` is implemented so far; the rest lands with
`victor run` (BACKLOG.md M1) — this module is where that logic will
live too, so `victor run` reuses the same injectable-client pattern
`enroll` establishes here rather than inventing a second one.
"""

from __future__ import annotations

import platform
import socket
from importlib.metadata import version as _pkg_version

import httpx

from victor_collector.models import CollectorCredentials

VERSION = _pkg_version("victor-collector")


class EnrollmentError(Exception):
    """Raised when the cloud API rejects, or can't be reached for, enrollment."""


def enroll(
    token: str,
    control_plane: str,
    *,
    client: httpx.Client | None = None,
) -> CollectorCredentials:
    """Exchange a one-time enrollment token for a long-lived collector
    credential — docs/collector-design.md §7.1. `client` is injectable
    so tests can pass an `httpx.MockTransport` instead of hitting a
    real network.
    """
    control_plane = control_plane.rstrip("/")
    payload = {
        "hostname": socket.gethostname(),
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "version": VERSION,
    }

    owns_client = client is None
    client = client or httpx.Client()
    try:
        try:
            response = client.post(
                f"{control_plane}/v1/collectors/enroll",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            raise EnrollmentError(f"Couldn't reach {control_plane}: {exc}") from exc
    finally:
        if owns_client:
            client.close()

    if response.status_code == 401:
        raise EnrollmentError("Enrollment token is invalid, expired, or already used.")
    if response.status_code == 403:
        detail = response.json().get("detail", "Collector limit reached for your tier.")
        raise EnrollmentError(detail)
    if response.status_code != 200:
        raise EnrollmentError(f"Enrollment failed ({response.status_code}): {response.text}")

    body = response.json()
    return CollectorCredentials(
        control_plane=control_plane,
        collector_id=body["collector_id"],
        credential=body["credential"],
        account_id=body["control_plane_id"],
        hostname=payload["hostname"],
    )
