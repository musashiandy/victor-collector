from victor_collector import credentials
from victor_collector.models import CollectorCredentials


def _sample() -> CollectorCredentials:
    return CollectorCredentials(
        control_plane="https://api.example.com",
        collector_id="col_123",
        credential="cred_abc",
        account_id="acct_1",
        hostname="test-host",
    )


def test_load_returns_none_when_no_file_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(credentials, "CREDENTIALS_PATH", tmp_path / "credentials.json")
    assert credentials.load() is None


def test_save_then_load_round_trips(tmp_path, monkeypatch):
    path = tmp_path / "victor" / "credentials.json"
    monkeypatch.setattr(credentials, "CREDENTIALS_PATH", path)

    creds = _sample()
    credentials.save(creds)

    loaded = credentials.load()
    assert loaded is not None
    assert loaded.collector_id == creds.collector_id
    assert loaded.credential == creds.credential
    assert loaded.control_plane == creds.control_plane
    assert loaded.account_id == creds.account_id


def test_save_creates_parent_directory(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "dir" / "credentials.json"
    monkeypatch.setattr(credentials, "CREDENTIALS_PATH", path)

    credentials.save(_sample())
    assert path.exists()
