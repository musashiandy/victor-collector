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
from pydantic import BaseModel

from victor_collector.models import CollectorCredentials, RawObservation

VERSION = _pkg_version("victor-collector")


class EnrollmentError(Exception):
    """Raised when the cloud API rejects, or can't be reached for, enrollment."""


class SyncError(Exception):
    """Raised when an authenticated call (heartbeat/tasks/observations)
    fails — network error, revoked credential, or unexpected response.
    """


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


def _authenticated_post(
    client: httpx.Client, creds: CollectorCredentials, path: str, json_body: dict
) -> httpx.Response:
    try:
        response = client.post(
            f"{creds.control_plane}{path}",
            headers={"Authorization": f"Bearer {creds.credential}"},
            json=json_body,
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"Couldn't reach {creds.control_plane}: {exc}") from exc
    if response.status_code == 401:
        raise SyncError("Collector credential is invalid or has been revoked.")
    return response


def _authenticated_get(
    client: httpx.Client, creds: CollectorCredentials, path: str
) -> httpx.Response:
    try:
        response = client.get(
            f"{creds.control_plane}{path}",
            headers={"Authorization": f"Bearer {creds.credential}"},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"Couldn't reach {creds.control_plane}: {exc}") from exc
    if response.status_code == 401:
        raise SyncError("Collector credential is invalid or has been revoked.")
    return response


def heartbeat(
    creds: CollectorCredentials,
    *,
    status: str,
    active_plugins: list[str] | None = None,
    client: httpx.Client | None = None,
) -> str:
    """POST /v1/collectors/heartbeat — docs/collector-design.md §7.2.
    Returns the server's min_supported_version.
    """
    owns_client = client is None
    client = client or httpx.Client()
    try:
        response = _authenticated_post(
            client,
            creds,
            "/v1/collectors/heartbeat",
            {"version": VERSION, "status": status, "active_plugins": active_plugins or []},
        )
    finally:
        if owns_client:
            client.close()

    if response.status_code != 200:
        raise SyncError(f"Heartbeat failed ({response.status_code}): {response.text}")
    return response.json()["min_supported_version"]


class TaskOut(BaseModel):
    task_id: str
    session_id: str
    plugin: str
    target: str
    safe_mode: bool
    claim_required: bool = False  # Older APIs do not advertise the lease protocol.


class TasksResponse(BaseModel):
    tasks: list[TaskOut]


def get_tasks(creds: CollectorCredentials, *, client: httpx.Client | None = None) -> TasksResponse:
    """GET /v1/collectors/tasks — docs/collector-design.md §7.3."""
    owns_client = client is None
    client = client or httpx.Client()
    try:
        response = _authenticated_get(client, creds, "/v1/collectors/tasks")
    finally:
        if owns_client:
            client.close()

    if response.status_code != 200:
        raise SyncError(f"Task poll failed ({response.status_code}): {response.text}")
    return TasksResponse.model_validate(response.json())


def upload_observations(
    creds: CollectorCredentials,
    *,
    session_id: str,
    task_id: str,
    observations: list[RawObservation],
    lease_token: str | None = None,
    client: httpx.Client | None = None,
) -> int:
    """POST /v1/sessions/{session_id}/observations —
    docs/collector-design.md §7.4. Returns the number of observations
    the server accepted.
    """
    body = {
        "task_id": task_id,
        "collector_version": VERSION,
        "observations": [
            {"id": obs.id, "collected_at": obs.collected_at.isoformat(), "plugin": obs.plugin,
             "target": obs.target, "raw": obs.raw, "redacted": obs.redacted}
            for obs in observations
        ],
    }
    if lease_token is not None:
        body["lease_token"] = lease_token
    owns_client = client is None
    client = client or httpx.Client()
    try:
        response = _authenticated_post(
            client, creds, f"/v1/sessions/{session_id}/observations", body
        )
    finally:
        if owns_client:
            client.close()

    if response.status_code != 202:
        raise SyncError(f"Observation upload failed ({response.status_code}): {response.text}")
    return response.json()["accepted"]


def claim_task(creds: CollectorCredentials, task_id: str, *, client: httpx.Client) -> str:
    response = _authenticated_post(client, creds, f"/v1/collectors/tasks/{task_id}/claim", {})
    if response.status_code != 200:
        raise SyncError(f"Task claim failed ({response.status_code}); another worker may own it")
    token = response.json().get("lease_token")
    if not isinstance(token, str) or not token:
        raise SyncError("Task claim returned no lease token")
    return token


def report_task_result(creds: CollectorCredentials, task_id: str, *, status: str,
                       lease_token: str, error: str | None = None, client: httpx.Client) -> None:
    response = _authenticated_post(client, creds, f"/v1/collectors/tasks/{task_id}/result",
                                   {"status": status, "lease_token": lease_token, "error": error})
    if response.status_code != 200:
        raise SyncError(f"Task result failed ({response.status_code})")
