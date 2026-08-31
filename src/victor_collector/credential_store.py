"""Named SSH credentials for `package-baseline-diff`
(docs/collector-design.md §15's resolved open question).

Each named credential is a plain JSON file at
~/.victor/credentials/<name>.json, mode 0600, populated by the operator
themselves — not generated, encrypted, or managed by the collector.
This matches how SSH itself already handles private keys
(~/.ssh/id_rsa: plaintext content, filesystem permissions as the only
protection) rather than adding an OS keyring dependency that doesn't
reliably work in the headless Docker containers this collector actually
ships to (no Secret Service/D-Bus session by default).
"""

from __future__ import annotations

from pathlib import Path

from victor_collector.models import SSHCredentialRef

CREDENTIALS_DIR = Path.home() / ".victor" / "credentials"


class CredentialNotFoundError(Exception):
    """Raised when a --credential-ref name has no matching file."""


def load(name: str, credentials_dir: Path | None = None) -> SSHCredentialRef:
    # Resolved from the module attribute at call time, not bound as a
    # default parameter value - callers (including tests) that
    # monkeypatch CREDENTIALS_DIR need this to actually take effect,
    # which a `credentials_dir: Path = CREDENTIALS_DIR` default would
    # silently defeat (default parameter values are captured once, at
    # def-time).
    credentials_dir = credentials_dir if credentials_dir is not None else CREDENTIALS_DIR
    path = credentials_dir / f"{name}.json"
    if not path.exists():
        raise CredentialNotFoundError(
            f"No credential named '{name}' at {path}. Create it yourself, e.g.:\n"
            '  {"username": "svc-baseline", "auth_method": "key", "key_path": "/path/to/key"}\n'
            "The collector never generates or stores secrets for target hosts."
        )
    return SSHCredentialRef.model_validate_json(path.read_text(encoding="utf-8"))
