"""SSH in, list installed packages, diff against a locally stored
baseline (docs/collector-design.md §5) — the one credentialed plugin.
Credential storage is a plain file at ~/.victor/credentials/<name>.json,
populated by the operator; see credential_store.py's module docstring
for why (resolving §15's open question).

parse_dpkg_output/parse_rpm_output/diff_packages are pure — no SSH
needed to test them, same execution/parsing split as every other
plugin. The SSH call itself isn't covered by an integration test: no
local test server, unlike tls_review's self-signed TLS fixture —
bootstrapping a real sshd is meaningfully heavier and out of scope for
this pass, matching how http_header_audit's real httpx.get() call isn't
tested against a live server either.

The baseline is established on a target's first run and never
overwritten automatically — a real "known-good" reference, not a
rolling diff against the previous run, which would hide slow drift.
"""

from __future__ import annotations

import re

import paramiko

from victor_collector import credential_store, storage
from victor_collector.models import RawObservation, SSHCredentialRef, Target
from victor_collector.plugins import PluginConfig, register

_DPKG_LINE_RE = re.compile(r"^(?P<status>\S{2,3})\s+(?P<name>\S+)\s+(?P<version>\S+)\s+\S+\s+.*$")


def parse_dpkg_output(text: str) -> dict[str, str]:
    """Parses `dpkg -l` output, keeping only fully-installed packages
    (status "ii") — not half-configured, removed-but-not-purged, etc."""
    packages: dict[str, str] = {}
    for line in text.splitlines():
        match = _DPKG_LINE_RE.match(line)
        if not match or not match.group("status").startswith("ii"):
            continue
        packages[match.group("name")] = match.group("version")
    return packages


def parse_rpm_output(text: str) -> dict[str, str]:
    """Parses `rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n'`."""
    packages: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            packages[parts[0]] = parts[1]
    return packages


def diff_packages(baseline: dict[str, str], current: dict[str, str]) -> dict:
    added = {n: v for n, v in current.items() if n not in baseline}
    removed = {n: v for n, v in baseline.items() if n not in current}
    changed = {
        n: {"from": baseline[n], "to": current[n]}
        for n in current
        if n in baseline and baseline[n] != current[n]
    }
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "baseline_package_count": len(baseline),
        "current_package_count": len(current),
        "drift_detected": bool(added or removed or changed),
    }


def _ssh_list_packages(
    host: str, cred: SSHCredentialRef, timeout: float = 20.0
) -> tuple[str, str]:
    """Real I/O — not unit tested, see module docstring. Returns
    (raw_output, package_manager)."""
    client = paramiko.SSHClient()
    # AutoAddPolicy: no known_hosts pinning yet - a documented v0.1
    # simplification, acceptable since this only ever targets a
    # customer's own already-authorized/confirmed asset (same trust
    # boundary as every other plugin), but a real gap if this needs
    # hardening later.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict = {"username": cred.username, "timeout": timeout}
        if cred.auth_method == "key":
            connect_kwargs["key_filename"] = cred.key_path
            if cred.key_passphrase:
                connect_kwargs["passphrase"] = cred.key_passphrase
        else:
            connect_kwargs["password"] = cred.password
        client.connect(host, **connect_kwargs)

        _, stdout, _ = client.exec_command("dpkg -l 2>/dev/null")
        output = stdout.read().decode("utf-8", errors="replace")
        if output.strip():
            return output, "dpkg"

        _, stdout, _ = client.exec_command(
            "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null"
        )
        return stdout.read().decode("utf-8", errors="replace"), "rpm"
    finally:
        client.close()


class PackageBaselineDiffPlugin:
    name = "package-baseline-diff"
    safe_mode = True
    requires_credentials = True

    def run(self, target: Target, config: PluginConfig) -> list[RawObservation]:
        credential_ref = config.get("credential_ref")
        if not credential_ref:
            raise RuntimeError(
                "package-baseline-diff requires --credential-ref <name> "
                "(see docs/collector-design.md §15)"
            )
        try:
            cred = credential_store.load(credential_ref)
        except credential_store.CredentialNotFoundError as exc:
            raise RuntimeError(str(exc)) from None

        try:
            output, manager = _ssh_list_packages(target.value, cred)
        except (paramiko.SSHException, OSError) as exc:
            raise RuntimeError(f"SSH to {target.value} failed: {exc}") from exc

        current = parse_dpkg_output(output) if manager == "dpkg" else parse_rpm_output(output)

        baseline = storage.get_package_baseline(target.value)
        if baseline is None:
            storage.save_package_baseline(target.value, current)
            raw = {
                "status": "baseline_established",
                "package_manager": manager,
                "package_count": len(current),
            }
        else:
            raw = {
                "status": "diffed",
                "package_manager": manager,
                **diff_packages(baseline, current),
            }

        return [RawObservation(plugin=self.name, target=target.value, raw=raw)]


register(PackageBaselineDiffPlugin())
