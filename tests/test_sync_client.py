import httpx
import pytest

from victor_collector import sync_client
from victor_collector.models import CollectorCredentials, RawObservation


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _creds() -> CollectorCredentials:
    return CollectorCredentials(
        control_plane="https://api.example.com",
        collector_id="col_123",
        credential="cred_abc",
        account_id="acct_1",
        hostname="test-host",
    )


def test_enroll_success_returns_credentials():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.example.com/v1/collectors/enroll"
        assert request.headers["authorization"] == "Bearer one-time-token"
        assert b"hostname" in request.content
        return httpx.Response(
            200,
            json={"collector_id": "col_123", "credential": "cred_abc", "control_plane_id": "acct_1"},
        )

    creds = sync_client.enroll(
        "one-time-token", "https://api.example.com", client=_client(handler)
    )
    assert creds.collector_id == "col_123"
    assert creds.credential == "cred_abc"
    assert creds.account_id == "acct_1"
    assert creds.control_plane == "https://api.example.com"
    assert creds.hostname


def test_enroll_strips_trailing_slash_from_control_plane():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"collector_id": "col_1", "credential": "cred_1", "control_plane_id": "acct_1"},
        )

    sync_client.enroll("t", "https://api.example.com/", client=_client(handler))
    assert seen["url"] == "https://api.example.com/v1/collectors/enroll"


def test_enroll_raises_on_invalid_or_expired_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "invalid"})

    with pytest.raises(sync_client.EnrollmentError, match="invalid, expired, or already used"):
        sync_client.enroll("bad-token", "https://api.example.com", client=_client(handler))


def test_enroll_raises_on_capacity_limit():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "Collector limit reached for the 'community' tier."})

    with pytest.raises(sync_client.EnrollmentError, match="Collector limit reached"):
        sync_client.enroll("t", "https://api.example.com", client=_client(handler))


def test_enroll_raises_on_unexpected_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with pytest.raises(sync_client.EnrollmentError, match="Enrollment failed \\(500\\)"):
        sync_client.enroll("t", "https://api.example.com", client=_client(handler))


def test_enroll_raises_on_network_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(sync_client.EnrollmentError, match="Couldn't reach"):
        sync_client.enroll("t", "https://api.example.com", client=_client(handler))


def test_heartbeat_sends_bearer_credential_and_returns_min_version():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.example.com/v1/collectors/heartbeat"
        assert request.headers["authorization"] == "Bearer cred_abc"
        return httpx.Response(200, json={"min_supported_version": "0.1.0"})

    result = sync_client.heartbeat(_creds(), status="idle", client=_client(handler))
    assert result == "0.1.0"


def test_heartbeat_raises_on_revoked_credential():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "revoked"})

    with pytest.raises(sync_client.SyncError, match="invalid or has been revoked"):
        sync_client.heartbeat(_creds(), status="idle", client=_client(handler))


def test_get_tasks_parses_task_list():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.example.com/v1/collectors/tasks"
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

    result = sync_client.get_tasks(_creds(), client=_client(handler))
    assert len(result.tasks) == 1
    assert result.tasks[0].task_id == "t_1"
    assert result.tasks[0].plugin == "service-inventory"


def test_get_tasks_returns_empty_list_when_nothing_pending():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"tasks": []})

    result = sync_client.get_tasks(_creds(), client=_client(handler))
    assert result.tasks == []


def test_upload_observations_sends_task_id_and_returns_accepted_count():
    obs = RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.example.com/v1/sessions/s_1/observations"
        import json

        body = json.loads(request.content)
        assert body["task_id"] == "t_1"
        assert body["observations"][0]["plugin"] == "service-inventory"
        return httpx.Response(202, json={"accepted": 1})

    accepted = sync_client.upload_observations(
        _creds(), session_id="s_1", task_id="t_1", observations=[obs], client=_client(handler)
    )
    assert accepted == 1


def test_upload_observations_raises_on_unexpected_status():
    obs = RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with pytest.raises(sync_client.SyncError, match="Observation upload failed"):
        sync_client.upload_observations(
            _creds(), session_id="s_1", task_id="t_1", observations=[obs], client=_client(handler)
        )
