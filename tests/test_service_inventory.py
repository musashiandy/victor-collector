"""Parser test — deliberately doesn't run real nmap (see module docstring
in service_inventory.py for why execution and parsing are split)."""

from victor_collector.plugins.service_inventory import parse_nmap_xml

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="9000">
        <state state="closed"/>
        <service name="cslistener"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_only_open_ports():
    observations = parse_nmap_xml(SAMPLE_NMAP_XML, target="10.10.10.25")
    assert len(observations) == 2
    ports = {o.raw["port"] for o in observations}
    assert ports == {22, 80}


def test_builds_banner_from_product_and_version():
    observations = parse_nmap_xml(SAMPLE_NMAP_XML, target="10.10.10.25")
    ssh = next(o for o in observations if o.raw["port"] == 22)
    assert ssh.raw["banner"] == "OpenSSH 7.4"
    assert ssh.plugin == "service-inventory"
    assert ssh.target == "10.10.10.25"


def test_falls_back_to_service_name_without_product():
    xml = """<?xml version="1.0"?>
    <nmaprun><host><ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports></host></nmaprun>
    """
    observations = parse_nmap_xml(xml, target="10.10.10.25")
    assert observations[0].raw["banner"] == "https"


def test_no_open_ports_returns_empty_list():
    xml = """<?xml version="1.0"?>
    <nmaprun><host><ports>
      <port protocol="tcp" portid="9000">
        <state state="filtered"/>
      </port>
    </ports></host></nmaprun>
    """
    assert parse_nmap_xml(xml, target="10.10.10.25") == []
