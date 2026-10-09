from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from victor_collector import policy
from victor_collector.cli import app


def test_missing_or_corrupted_policy_fails_closed():
    with pytest.raises(policy.PolicyError):
        policy.assert_allowed("host", "tls-review")
    policy.POLICY_PATH.write_text("not JSON", encoding="utf-8")
    with pytest.raises(policy.PolicyError):
        policy.assert_allowed("host", "tls-review")


def test_target_plugin_and_expiry_are_independently_enforced():
    policy.authorize("host", "2099-01-01T00:00:00Z", ["tls-review"])
    policy.assert_allowed("host", "tls-review")
    for target, plugin in [("other-host", "tls-review"), ("host", "service-inventory")]:
        with pytest.raises(policy.PolicyError):
            policy.assert_allowed(target, plugin)
    with pytest.raises(policy.PolicyError):
        policy.assert_allowed("host", "tls-review", now=datetime(2100, 1, 1, tzinfo=timezone.utc))


def test_cli_authorization_smoke_test_and_replacement():
    runner = CliRunner()
    result = runner.invoke(app, ["authorize", "host", "--expires", "2099-01-01T00:00:00Z", "--plugins", "tls-review"])
    assert result.exit_code == 0, result.output
    policy.assert_allowed("host", "tls-review")
    policy.authorize("host", "2099-01-01T00:00:00Z", ["http-header-audit"])
    with pytest.raises(policy.PolicyError):
        policy.assert_allowed("host", "tls-review")
    policy.assert_allowed("host", "http-header-audit")
    assert runner.invoke(app, ["authorize", "--script=bad", "--expires", "2099-01-01T00:00:00Z"]).exit_code != 0
