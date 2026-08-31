from victor_collector.plugins.tls_review import probe_tls


def test_detects_supported_modern_protocol(tls_test_server):
    host, port = tls_test_server
    result = probe_tls(host, port, timeout=2)
    assert "TLSv1.2" in result["protocols_supported"] or "TLSv1.3" in result["protocols_supported"]


def test_captures_certificate_subject(tls_test_server):
    host, port = tls_test_server
    result = probe_tls(host, port, timeout=2)
    assert result["certificate"]["subject"] is not None


def test_unreachable_host_returns_no_supported_protocols():
    # Port 1 on localhost should refuse immediately rather than hang.
    result = probe_tls("127.0.0.1", 1, timeout=1)
    assert result["protocols_supported"] == []
