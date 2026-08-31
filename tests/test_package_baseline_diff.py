from __future__ import annotations

import pytest

from victor_collector import credential_store, storage
from victor_collector.models import SSHCredentialRef, Target
from victor_collector.plugins import PluginConfig
from victor_collector.plugins.package_baseline_diff import (
    PackageBaselineDiffPlugin,
    diff_packages,
    parse_dpkg_output,
    parse_rpm_output,
)

DPKG_SAMPLE = """Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version      Architecture Description
+++-==============-============-============-=================================
ii  adduser        3.118        all          add and remove users and groups
ii  apt            2.2.4        amd64        commandline package manager
rc  old-pkg        1.0          amd64        removed but not purged
"""

RPM_SAMPLE = """bash 5.1.8-4.el9
coreutils 8.32-31.el9
openssh 8.7p1-34.el9
"""


# --- parsing -----------------------------------------------------------


def test_parse_dpkg_output_keeps_only_fully_installed_packages():
    result = parse_dpkg_output(DPKG_SAMPLE)
    assert result == {"adduser": "3.118", "apt": "2.2.4"}
    assert "old-pkg" not in result


def test_parse_rpm_output():
    result = parse_rpm_output(RPM_SAMPLE)
    assert result == {
        "bash": "5.1.8-4.el9",
        "coreutils": "8.32-31.el9",
        "openssh": "8.7p1-34.el9",
    }


def test_parse_dpkg_output_handles_empty_input():
    assert parse_dpkg_output("") == {}


# --- diffing -------------------------------------------------------------


def test_diff_packages_detects_added_removed_and_changed():
    baseline = {"a": "1.0", "b": "2.0", "c": "3.0"}
    current = {"a": "1.0", "b": "2.1", "d": "4.0"}  # b changed, c removed, d added

    diff = diff_packages(baseline, current)

    assert diff["added"] == {"d": "4.0"}
    assert diff["removed"] == {"c": "3.0"}
    assert diff["changed"] == {"b": {"from": "2.0", "to": "2.1"}}
    assert diff["drift_detected"] is True
    assert diff["baseline_package_count"] == 3
    assert diff["current_package_count"] == 3


def test_diff_packages_no_drift_when_identical():
    packages = {"a": "1.0", "b": "2.0"}
    diff = diff_packages(packages, dict(packages))
    assert diff["drift_detected"] is False
    assert diff["added"] == {}
    assert diff["removed"] == {}
    assert diff["changed"] == {}


# --- credential store ------------------------------------------------------


def test_credential_store_raises_when_missing(tmp_path):
    with pytest.raises(credential_store.CredentialNotFoundError, match="prod-host"):
        credential_store.load("prod-host", credentials_dir=tmp_path)


def test_credential_store_loads_a_real_file(tmp_path):
    (tmp_path / "prod-host.json").write_text(
        '{"username": "svc", "auth_method": "password", "password": "hunter2"}',
        encoding="utf-8",
    )
    cred = credential_store.load("prod-host", credentials_dir=tmp_path)
    assert cred.username == "svc"
    assert cred.auth_method == "password"
    assert cred.password == "hunter2"


# --- storage: baseline persistence ------------------------------------------


def test_baseline_round_trips(tmp_path):
    db_path = tmp_path / "collector.db"
    assert storage.get_package_baseline("10.10.10.25", db_path) is None

    storage.save_package_baseline("10.10.10.25", {"a": "1.0"}, db_path)
    assert storage.get_package_baseline("10.10.10.25", db_path) == {"a": "1.0"}


def test_baseline_is_not_overwritten_by_a_second_save_unless_explicit(tmp_path):
    db_path = tmp_path / "collector.db"
    storage.save_package_baseline("host", {"a": "1.0"}, db_path)
    storage.save_package_baseline("host", {"a": "2.0"}, db_path)  # explicit re-save is allowed
    assert storage.get_package_baseline("host", db_path) == {"a": "2.0"}


# --- plugin.run() orchestration (SSH call mocked - see module docstring) ---


def test_plugin_requires_credential_ref():
    plugin = PackageBaselineDiffPlugin()
    with pytest.raises(RuntimeError, match="--credential-ref"):
        plugin.run(Target(value="10.10.10.25"), PluginConfig())


def test_plugin_raises_clear_error_for_unknown_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(credential_store, "CREDENTIALS_DIR", tmp_path)
    plugin = PackageBaselineDiffPlugin()
    with pytest.raises(RuntimeError, match="No credential named"):
        plugin.run(Target(value="10.10.10.25"), PluginConfig({"credential_ref": "missing"}))


def _fake_baseline_store(monkeypatch, initial: dict[str, dict[str, str]] | None = None) -> dict:
    """storage.get_package_baseline/save_package_baseline both take
    db_path as a default *parameter* bound at def-time, so
    monkeypatching storage.DEFAULT_DB_PATH silently does nothing (and
    would otherwise risk writing to the real ~/.victor/collector.db).
    Patching the functions themselves is the correct, safe target."""
    saved: dict[str, dict[str, str]] = dict(initial or {})
    monkeypatch.setattr(storage, "get_package_baseline", lambda target: saved.get(target))
    monkeypatch.setattr(
        storage, "save_package_baseline", lambda target, pkgs: saved.__setitem__(target, pkgs)
    )
    return saved


def test_plugin_establishes_baseline_on_first_run(tmp_path, monkeypatch):
    monkeypatch.setattr(credential_store, "CREDENTIALS_DIR", tmp_path)
    (tmp_path / "prod.json").write_text(
        '{"username": "svc", "auth_method": "password", "password": "x"}', encoding="utf-8"
    )
    saved = _fake_baseline_store(monkeypatch)

    import victor_collector.plugins.package_baseline_diff as module

    monkeypatch.setattr(
        module, "_ssh_list_packages", lambda host, cred: ("ii  a  1.0  amd64  desc\n", "dpkg")
    )

    plugin = PackageBaselineDiffPlugin()
    observations = plugin.run(Target(value="10.10.10.25"), PluginConfig({"credential_ref": "prod"}))

    assert len(observations) == 1
    assert observations[0].raw["status"] == "baseline_established"
    assert observations[0].raw["package_count"] == 1
    assert saved["10.10.10.25"] == {"a": "1.0"}


def test_plugin_diffs_against_existing_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(credential_store, "CREDENTIALS_DIR", tmp_path)
    (tmp_path / "prod.json").write_text(
        '{"username": "svc", "auth_method": "password", "password": "x"}', encoding="utf-8"
    )
    _fake_baseline_store(monkeypatch, {"10.10.10.25": {"a": "1.0"}})

    import victor_collector.plugins.package_baseline_diff as module

    monkeypatch.setattr(
        module,
        "_ssh_list_packages",
        lambda host, cred: ("ii  a  1.0  amd64  desc\nii  b  2.0  amd64  desc\n", "dpkg"),
    )

    plugin = PackageBaselineDiffPlugin()
    observations = plugin.run(Target(value="10.10.10.25"), PluginConfig({"credential_ref": "prod"}))

    raw = observations[0].raw
    assert raw["status"] == "diffed"
    assert raw["added"] == {"b": "2.0"}
    assert raw["drift_detected"] is True
