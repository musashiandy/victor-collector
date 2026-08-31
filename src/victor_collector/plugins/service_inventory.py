"""Port scan + banner grab via nmap.

nmap is GPL-licensed, so it's invoked as a subprocess (a system-installed
dependency the operator brings) — never vendored or statically linked. See
docs/collector-design.md §5 in the victor-recon-console repo for why.

Parsing is split from execution on purpose: `parse_nmap_xml` takes no
subprocess dependency, so it's testable without nmap installed.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from victor_collector.models import RawObservation, Target
from victor_collector.plugins import PluginConfig, register

DEFAULT_TIMEOUT_SECONDS = 120


def _run_nmap(target: str, timeout: int) -> str:
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap not found on PATH. service-inventory requires a system-installed "
            "nmap (e.g. `apt install nmap`, `brew install nmap`, or the Windows "
            "installer from nmap.org) — it is never bundled with the collector."
        )

    result = subprocess.run(
        ["nmap", "-sV", "-oX", "-", target],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nmap exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def parse_nmap_xml(xml_output: str, target: str) -> list[RawObservation]:
    """Turn nmap's -oX output into one RawObservation per open port."""
    root = ET.fromstring(xml_output)
    observations: list[RawObservation] = []

    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            name = service.get("name", "") if service is not None else ""
            banner = " ".join(p for p in (product, version) if p) or name

            observations.append(
                RawObservation(
                    plugin="service-inventory",
                    target=target,
                    raw={
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "service": name,
                        "product": product,
                        "version": version,
                        "banner": banner,
                    },
                )
            )

    return observations


class ServiceInventoryPlugin:
    name = "service-inventory"
    safe_mode = True
    requires_credentials = False

    def run(self, target: Target, config: PluginConfig) -> list[RawObservation]:
        timeout = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        xml_output = _run_nmap(target.value, timeout)
        return parse_nmap_xml(xml_output, target.value)


register(ServiceInventoryPlugin())
