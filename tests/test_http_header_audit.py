import httpx

from victor_collector.plugins.http_header_audit import analyze_headers


def test_cloud_config_does_not_follow_redirects(monkeypatch):
    from victor_collector.plugins.http_header_audit import HttpHeaderAuditPlugin
    from victor_collector.models import Target
    calls = []
    def get(url, **kwargs):
        calls.append(kwargs)
        return httpx.Response(302, headers={"Location": "https://other.example"}, request=httpx.Request("GET", url))
    monkeypatch.setattr(httpx, "get", get)
    result = HttpHeaderAuditPlugin().run(Target(value="https://example.com"), {"follow_redirects": False})
    assert calls[0]["follow_redirects"] is False
    assert result[0].raw["status_code"] == 302
    assert result[0].target == "https://example.com"


def test_flags_all_missing_headers_when_none_present():
    headers = httpx.Headers({"content-type": "text/html"})
    result = analyze_headers(headers, "https://example.com")
    assert result["present_headers"] == {}
    assert len(result["missing_headers"]) == 5


def test_recognizes_present_headers_case_insensitively():
    headers = httpx.Headers(
        {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        }
    )
    result = analyze_headers(headers, "https://example.com")
    assert result["present_headers"]["Content-Security-Policy"] == "default-src 'self'"
    assert "X-Frame-Options" in result["present_headers"]
    assert "Content-Security-Policy" not in result["missing_headers"]
    assert len(result["missing_headers"]) == 3


def test_all_headers_present_means_nothing_missing():
    headers = httpx.Headers(
        {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }
    )
    result = analyze_headers(headers, "https://example.com")
    assert result["missing_headers"] == []
    assert len(result["present_headers"]) == 5
