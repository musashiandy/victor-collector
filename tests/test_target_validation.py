import pytest
from victor_collector.target_validation import validate_target
from victor_collector.policy import PolicyError, assert_allowed


@pytest.mark.parametrize("target", ["10.0.0.1-10", "10.0.0.0/24", "10.0.0.1,10.0.0.2", "10.0.0.*", "--script=all", "https://user:secret@example.com", "example.com other.com"])
def test_refuses_ranges_lists_and_credentials(target):
    with pytest.raises(ValueError):
        validate_target(target)


def test_url_cannot_be_used_as_nmap_or_tls_host():
    with pytest.raises(PolicyError):
        assert_allowed("https://example.com", "service-inventory")
