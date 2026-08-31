import httpx
import pytest

from victor_collector import sync_client


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


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
