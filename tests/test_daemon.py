from __future__ import annotations

import json

import httpx
import pytest

from victor_collector import daemon, sync_client
from victor_collector.models import CollectorCredentials, RawObservation, Target


def _creds() -> CollectorCredentials:
    return CollectorCredentials(
        control_plane="https://api.example.com",
        collector_id="col_123",
        credential="cred_abc",
        account_id="acct_1",
        hostname="test-host",
    )


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


class _FakePlugin:
    def __init__(self, name="service-inventory", safe_mode=True, observations=None, error=None):
        self.name = name
        self.safe_mode = safe_mode
        self.requires_credentials = False
        self._observations = observations if observations is not None else []
        self._error = error

    def run(self, target: Target, config) -> list[RawObservation]:
        if self._error:
            raise self._error
        return self._observations


def test_run_once_heartbeats_when_idle_and_interval_elapsed():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/tasks"):
            return httpx.Response(200, json={"tasks": []})
        return httpx.Response(200, json={"min_supported_version": "0.1.0"})

    new_last_heartbeat = daemon.run_once(
        _creds(), _client(handler), last_heartbeat_at=0.0, now=100.0
    )
    assert new_last_heartbeat == 100.0
    assert any(p.endswith("/heartbeat") for p in calls)


def test_run_once_skips_heartbeat_when_interval_not_elapsed():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"tasks": []})

    new_last_heartbeat = daemon.run_once(
        _creds(), _client(handler), last_heartbeat_at=100.0, now=110.0
    )
    assert new_last_heartbeat == 100.0
    assert not any(p.endswith("/heartbeat") for p in calls)


def test_run_once_executes_task_and_uploads_redacted_observations(monkeypatch):
    monkeypatch.setattr(
        daemon.redaction,
        "redact_observation",
        lambda obs, *, session_id: obs.model_copy(update={"redacted": True, "target": "IP-xxxx"}),
    )
    fake_plugin = _FakePlugin(
        observations=[RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})]
    )
    monkeypatch.setattr(daemon.plugin_registry, "get", lambda name: fake_plugin)

    uploaded = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/tasks"):
            return httpx.Response(
                200,
                json={
                    "tasks": [
                        {
                            "task_id": "t_1",
                            "session_id": "s_1",
                            "plugin": "service-inventory",
                            "target": "10.10.10.25",
                            "safe_mode": True,
                        }
                    ]
                },
            )
        if path.endswith("/heartbeat"):
            return httpx.Response(200, json={"min_supported_version": "0.1.0"})
        if path.endswith("/observations"):
            uploaded["body"] = json.loads(request.content)
            return httpx.Response(202, json={"accepted": 1})
        raise AssertionError(f"unexpected request to {path}")

    events = []
    daemon.run_once(_creds(), _client(handler), last_heartbeat_at=0.0, now=0.0, on_event=events.append)

    assert uploaded["body"]["task_id"] == "t_1"
    assert uploaded["body"]["observations"][0]["redacted"] is True
    assert any("uploaded 1 redacted observation" in e for e in events)


def test_run_once_skips_unknown_plugin_without_crashing(monkeypatch):
    def raise_unknown(name):
        raise ValueError(f"Unknown plugin '{name}'.")

    monkeypatch.setattr(daemon.plugin_registry, "get", raise_unknown)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tasks"):
            return httpx.Response(
                200,
                json={
                    "tasks": [
                        {
                            "task_id": "t_1",
                            "session_id": "s_1",
                            "plugin": "nonexistent",
                            "target": "10.10.10.25",
                            "safe_mode": True,
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"min_supported_version": "0.1.0"})

    events = []
    daemon.run_once(_creds(), _client(handler), last_heartbeat_at=0.0, now=0.0, on_event=events.append)
    assert any("skipping task t_1" in e for e in events)


def test_run_once_skips_unsafe_plugin_when_task_did_not_authorize_it(monkeypatch):
    # An inherently non-safe plugin (safe_mode=False) may only run its
    # non-safe actions when the task explicitly authorizes that
    # (task.safe_mode=False). Here the task insists on safe_mode=True,
    # so the plugin must be refused - collector-design.md §5.
    fake_plugin = _FakePlugin(safe_mode=False)
    monkeypatch.setattr(daemon.plugin_registry, "get", lambda name: fake_plugin)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tasks"):
            return httpx.Response(
                200,
                json={
                    "tasks": [
                        {
                            "task_id": "t_1",
                            "session_id": "s_1",
                            "plugin": "service-inventory",
                            "target": "10.10.10.25",
                            "safe_mode": True,
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"min_supported_version": "0.1.0"})

    events = []
    daemon.run_once(_creds(), _client(handler), last_heartbeat_at=0.0, now=0.0, on_event=events.append)
    assert any("didn't authorize that" in e for e in events)


def test_run_once_survives_plugin_runtime_error(monkeypatch):
    fake_plugin = _FakePlugin(error=RuntimeError("scan failed"))
    monkeypatch.setattr(daemon.plugin_registry, "get", lambda name: fake_plugin)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tasks"):
            return httpx.Response(
                200,
                json={
                    "tasks": [
                        {
                            "task_id": "t_1",
                            "session_id": "s_1",
                            "plugin": "service-inventory",
                            "target": "10.10.10.25",
                            "safe_mode": True,
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"min_supported_version": "0.1.0"})

    events = []
    daemon.run_once(_creds(), _client(handler), last_heartbeat_at=0.0, now=0.0, on_event=events.append)
    assert any("scan failed" in e for e in events)


def test_run_once_survives_upload_failure(monkeypatch):
    monkeypatch.setattr(
        daemon.redaction,
        "redact_observation",
        lambda obs, *, session_id: obs.model_copy(update={"redacted": True}),
    )
    fake_plugin = _FakePlugin(
        observations=[RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})]
    )
    monkeypatch.setattr(daemon.plugin_registry, "get", lambda name: fake_plugin)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/tasks"):
            return httpx.Response(
                200,
                json={
                    "tasks": [
                        {
                            "task_id": "t_1",
                            "session_id": "s_1",
                            "plugin": "service-inventory",
                            "target": "10.10.10.25",
                            "safe_mode": True,
                        }
                    ]
                },
            )
        if path.endswith("/heartbeat"):
            return httpx.Response(200, json={"min_supported_version": "0.1.0"})
        if path.endswith("/observations"):
            return httpx.Response(500, text="boom")
        raise AssertionError(f"unexpected request to {path}")

    events = []
    # Should not raise even though the upload fails.
    daemon.run_once(_creds(), _client(handler), last_heartbeat_at=0.0, now=0.0, on_event=events.append)
    assert any("upload failed" in e for e in events)
