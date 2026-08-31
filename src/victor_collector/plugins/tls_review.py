"""TLS handshake + protocol/cipher enumeration.

Probes each protocol version separately so we can tell the difference
between "server refuses legacy TLS" (good) and "server only speaks one
version we didn't test" (untested) — a single default handshake can't
distinguish those. Network I/O (`_probe_version`) is split from the pure
`build_observation` so the latter is unit-testable without a live server.
"""

from __future__ import annotations

import socket
import ssl

from cryptography import x509

from victor_collector.models import RawObservation, Target
from victor_collector.plugins import PluginConfig, register

DEFAULT_PORT = 443
DEFAULT_TIMEOUT_SECONDS = 10

_PROTOCOL_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# Legacy protocols a modern OpenSSL build may refuse to even attempt
# regardless of target support — reported as "untested", not "absent".
_LEGACY = {"TLSv1", "TLSv1.1"}


def _probe_version(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> str | None:
    """Returns the negotiated cipher name if this version is accepted, else None."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = version
    ctx.maximum_version = version
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cipher = ssock.cipher()
            return cipher[0] if cipher else None


def probe_tls(host: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Real network I/O — attempts each protocol version in turn."""
    supported: dict[str, str] = {}
    untestable: list[str] = []

    for name, version in _PROTOCOL_VERSIONS.items():
        try:
            cipher = _probe_version(host, port, version, timeout)
            if cipher:
                supported[name] = cipher
        except (ssl.SSLError, OSError, ValueError):
            # Can't tell from here whether the server refused this protocol
            # or our own OpenSSL build won't even attempt it (common for
            # TLSv1/1.1 on modern systems) — report legacy versions as
            # untestable rather than confidently claiming "not supported".
            if name in _LEGACY:
                untestable.append(name)

    cert_info: dict = {}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # getpeercert() (the dict form) only populates fields when
                # the chain was actually validated — with CERT_NONE it's
                # always {}. binary_form=True gets the raw cert regardless
                # of trust, which we then parse ourselves: we're doing
                # recon, not making a trust decision.
                der = ssock.getpeercert(binary_form=True)
                if der:
                    parsed = x509.load_der_x509_certificate(der)
                    cert_info = {
                        "subject": parsed.subject.rfc4514_string(),
                        "issuer": parsed.issuer.rfc4514_string(),
                        "not_valid_after": parsed.not_valid_after_utc.isoformat(),
                    }
    except (OSError, ssl.SSLError, ValueError):
        pass

    return {
        "port": port,
        "protocols_supported": list(supported.keys()),
        "cipher_by_protocol": supported,
        "protocols_untestable": untestable,
        "certificate": cert_info,
    }


class TlsReviewPlugin:
    name = "tls-review"
    safe_mode = True
    requires_credentials = False

    def run(self, target: Target, config: PluginConfig) -> list[RawObservation]:
        port = config.get("port", DEFAULT_PORT)
        timeout = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        raw = probe_tls(target.value, port=port, timeout=timeout)
        return [RawObservation(plugin=self.name, target=f"{target.value}:{port}", raw=raw)]


register(TlsReviewPlugin())
