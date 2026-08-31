from victor_collector import redaction
from victor_collector.models import RawObservation


def test_redacts_ip_target_and_marks_redacted(tmp_path):
    obs = RawObservation(
        plugin="service-inventory", target="10.10.10.25", raw={"port": 22, "banner": "OpenSSH"}
    )
    result = redaction.redact_observation(obs, session_id="s1", db_path=tmp_path / "map.db")
    assert result.redacted is True
    assert result.target.startswith("IP-")
    assert result.target != "10.10.10.25"


def test_redacts_hostname_target_exact_match(tmp_path):
    obs = RawObservation(plugin="tls-review", target="internal.example.com", raw={"cn": "internal.example.com"})
    result = redaction.redact_observation(obs, session_id="s1", db_path=tmp_path / "map.db")
    assert result.target.startswith("HOST-")
    assert result.raw["cn"] == result.target  # same pseudonym, both occurrences


def test_redacts_ip_embedded_in_free_text(tmp_path):
    obs = RawObservation(
        plugin="service-inventory",
        target="example.com",
        raw={"banner": "resolved to 10.10.10.25 on port 22"},
    )
    result = redaction.redact_observation(obs, session_id="s1", db_path=tmp_path / "map.db")
    assert "10.10.10.25" not in result.raw["banner"]
    assert "IP-" in result.raw["banner"]


def test_pseudonyms_are_stable_within_a_session(tmp_path):
    db_path = tmp_path / "map.db"
    obs1 = RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})
    obs2 = RawObservation(plugin="tls-review", target="10.10.10.25", raw={"port": 443})

    r1 = redaction.redact_observation(obs1, session_id="s1", db_path=db_path)
    r2 = redaction.redact_observation(obs2, session_id="s1", db_path=db_path)
    assert r1.target == r2.target  # same real value, same session -> same pseudonym


def test_pseudonyms_differ_across_sessions(tmp_path):
    db_path = tmp_path / "map.db"
    obs = RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})

    r1 = redaction.redact_observation(obs, session_id="s1", db_path=db_path)
    r2 = redaction.redact_observation(obs, session_id="s2", db_path=db_path)
    assert r1.target != r2.target


def test_redacts_nested_lists_and_dicts(tmp_path):
    obs = RawObservation(
        plugin="service-inventory",
        target="10.10.10.25",
        raw={"hosts": [{"ip": "10.10.10.25", "notes": ["seen at 10.10.10.25"]}]},
    )
    result = redaction.redact_observation(obs, session_id="s1", db_path=tmp_path / "map.db")
    assert "10.10.10.25" not in str(result.raw)


def test_original_observation_is_not_mutated(tmp_path):
    obs = RawObservation(plugin="service-inventory", target="10.10.10.25", raw={"port": 22})
    redaction.redact_observation(obs, session_id="s1", db_path=tmp_path / "map.db")
    assert obs.target == "10.10.10.25"
    assert obs.redacted is False
