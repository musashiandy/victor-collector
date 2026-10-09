import json

import httpx

from victor_collector import daemon
from victor_collector.models import RawObservation
from tests.test_daemon import _FakePlugin, _creds


def test_advertised_lease_is_claimed_before_execution_and_preserves_source_identity(monkeypatch):
    obs = RawObservation(plugin="service-inventory", target="host", raw={"port": 22})
    monkeypatch.setattr(daemon.plugin_registry, "get", lambda name: _FakePlugin(observations=[obs]))
    monkeypatch.setattr(daemon.redaction, "redact_observation", lambda observation, *, session_id: observation.model_copy(update={"redacted": True, "target": "HOST-redacted"}))
    calls = []

    def handler(request):
        calls.append((request.url.path, json.loads(request.content) if request.content else {}))
        if request.url.path.endswith("/tasks"):
            return httpx.Response(200, json={"tasks": [{"task_id": "t1", "session_id": "s1", "plugin": "service-inventory", "target": "host", "safe_mode": True, "claim_required": True}]})
        if request.url.path.endswith("/claim"):
            return httpx.Response(200, json={"lease_token": "lease-1", "lease_until": 1000})
        if request.url.path.endswith("/heartbeat"):
            return httpx.Response(200, json={"min_supported_version": "0.1.0"})
        if request.url.path.endswith("/observations"):
            return httpx.Response(202, json={"accepted": 1})
        raise AssertionError(request.url.path)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        daemon.run_once(_creds(), client, 0, now=100)
    assert [path.rsplit("/", 1)[-1] for path, _ in calls] == ["tasks", "claim", "heartbeat", "observations"]
    upload = calls[-1][1]
    assert upload["lease_token"] == "lease-1"
    assert upload["observations"][0]["id"] == obs.id
    assert upload["observations"][0]["collected_at"] == obs.collected_at.isoformat()


def test_empty_or_failed_plugin_reports_terminal_outcome_without_secret_error(monkeypatch):
    for failure, expected in [(None, "empty"), (RuntimeError("secret-target-password"), "failed")]:
        monkeypatch.setattr(daemon.plugin_registry, "get", lambda name: _FakePlugin(error=failure))
        results = []

        def handler(request):
            if request.url.path.endswith("/tasks"):
                return httpx.Response(200, json={"tasks": [{"task_id": "t1", "session_id": "s1", "plugin": "service-inventory", "target": "host", "safe_mode": True, "claim_required": True}]})
            if request.url.path.endswith("/claim"):
                return httpx.Response(200, json={"lease_token": "lease-1"})
            if request.url.path.endswith("/result"):
                results.append(json.loads(request.content))
                return httpx.Response(200, json={"status": expected})
            return httpx.Response(200, json={"min_supported_version": "0.1.0"})

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            daemon.run_once(_creds(), client, 0, now=100)
        assert results[0]["status"] == expected
        assert "secret-target-password" not in json.dumps(results)
