"""Cloud-connected daemon loop (docs/collector-design.md §7.2–§7.4):
heartbeat, poll for tasks, run the matching plugin, redact, upload.

Uses a plain synchronous loop with `time.sleep`, not asyncio — the
design doc proposed asyncio, but every piece this calls (sync_client's
`httpx.Client`, plugins' `run()`, redaction's sqlite calls) is already
synchronous, and the loop only ever runs one task at a time
(collector-design.md §15's proposed backpressure default), so there's
no concurrent I/O here that would justify an async client just for
this loop.
"""

from __future__ import annotations

import time
from typing import Callable

import httpx

from victor_collector import plugins as plugin_registry
from victor_collector import policy, redaction, sync_client
from victor_collector.models import CollectorCredentials, RawObservation, Target
from victor_collector.plugins import PluginConfig
from victor_collector.sync_client import TaskOut

HEARTBEAT_INTERVAL_SECONDS = 60
POLL_INTERVAL_SECONDS = 15

EventCallback = Callable[[str], None]

_NOOP: EventCallback = lambda _msg: None  # noqa: E731


def _execute_task(
    creds: CollectorCredentials,
    client: httpx.Client,
    task: TaskOut,
    *,
    on_event: EventCallback,
    lease_token: str | None = None,
) -> None:
    def terminal(status: str, message: str | None = None) -> None:
        if lease_token is not None:
            sync_client.report_task_result(creds, task.task_id, status=status,
                                           lease_token=lease_token, error=message, client=client)

    try:
        policy.assert_allowed(task.target, task.plugin)
    except policy.PolicyError as exc:
        on_event(f"skipping task {task.task_id}: {exc}")
        terminal("failed", "Collector local authorization refused this task; run victor authorize locally")
        return

    try:
        plugin = plugin_registry.get(task.plugin)
    except ValueError as exc:
        on_event(f"skipping task {task.task_id}: {exc}")
        terminal("failed", "Plugin is not available on this collector")
        return

    # collector-design.md §5: a plugin that can do non-safe things
    # (plugin.safe_mode is False) only gets to do them if the task's own
    # scope explicitly authorized non-safe-mode (task.safe_mode is
    # False). Defense in depth against a compromised/misconfigured
    # control plane, independent of whatever the cloud side intended.
    if not plugin.safe_mode and task.safe_mode:
        on_event(
            f"skipping task {task.task_id}: plugin '{task.plugin}' can perform non-safe-mode "
            "actions, but this task didn't authorize that"
        )
        terminal("failed", "Plugin refused by collector safe-mode policy")
        return

    try:
        observations: list[RawObservation] = plugin.run(Target(value=task.target), PluginConfig(follow_redirects=False))
    except Exception as exc:
        on_event(f"task {task.task_id} ({task.plugin}) failed: {exc}")
        # Never upload raw exception strings: they may contain a target or secret.
        terminal("failed", "Plugin execution failed; inspect collector logs locally")
        return

    if not observations:
        on_event(f"task {task.task_id}: no observations produced")
        terminal("empty")
        return

    redacted = [
        redaction.redact_observation(obs, session_id=task.session_id) for obs in observations
    ]

    try:
        accepted = sync_client.upload_observations(
            creds,
            session_id=task.session_id,
            task_id=task.task_id,
            observations=redacted,
            lease_token=lease_token,
            client=client,
        )
    except sync_client.SyncError as exc:
        on_event(f"task {task.task_id}: upload failed, will not retry this cycle: {exc}")
        return

    on_event(f"task {task.task_id}: uploaded {accepted} redacted observation(s)")


def run_once(
    creds: CollectorCredentials,
    client: httpx.Client,
    last_heartbeat_at: float,
    *,
    now: float | None = None,
    on_event: EventCallback = _NOOP,
) -> float:
    """One poll + (maybe) heartbeat + (maybe) run-a-task cycle. Returns
    the new `last_heartbeat_at`. Split out from `run_forever()` so it's
    testable without a real clock or real sleeps.
    """
    now = time.monotonic() if now is None else now

    tasks = sync_client.get_tasks(creds, client=client).tasks
    if not tasks:
        if now - last_heartbeat_at >= HEARTBEAT_INTERVAL_SECONDS:
            min_version = sync_client.heartbeat(creds, status="idle", client=client)
            if min_version > sync_client.VERSION:
                on_event(
                    f"server wants >= {min_version}, running {sync_client.VERSION} — "
                    "update when convenient, not forced"
                )
            return now
        return last_heartbeat_at

    task = tasks[0]  # one active plugin run at a time — collector-design.md §15
    lease_token = sync_client.claim_task(creds, task.task_id, client=client) if task.claim_required else None
    sync_client.heartbeat(creds, status="running", active_plugins=[task.plugin], client=client)
    on_event(f"task {task.task_id}: running {task.plugin} against {task.target}")
    _execute_task(creds, client, task, on_event=on_event, lease_token=lease_token)
    return now


def run_forever(creds: CollectorCredentials, *, on_event: EventCallback = _NOOP) -> None:
    """Blocking loop. Poll every POLL_INTERVAL_SECONDS; heartbeat at
    HEARTBEAT_INTERVAL_SECONDS while idle, immediately on picking up a
    task. Raises KeyboardInterrupt up to the caller on Ctrl+C — the CLI
    command is responsible for the clean-shutdown message.
    """
    on_event(
        f"starting — heartbeat every {HEARTBEAT_INTERVAL_SECONDS}s idle, "
        f"poll every {POLL_INTERVAL_SECONDS}s"
    )
    last_heartbeat_at = 0.0
    with httpx.Client() as client:
        while True:
            try:
                last_heartbeat_at = run_once(creds, client, last_heartbeat_at, on_event=on_event)
            except sync_client.SyncError as exc:
                on_event(f"sync error, will retry next cycle: {exc}")
            time.sleep(POLL_INTERVAL_SECONDS)
