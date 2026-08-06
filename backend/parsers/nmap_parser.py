"""Normalize Nmap XML service observations into VulnerabilityItem records."""

import io
from typing import BinaryIO

from defusedxml import ElementTree as DefusedET

from backend.models.schemas import Severity, VulnerabilityItem


def parse_nmap_xml(file_obj: BinaryIO | bytes) -> list[VulnerabilityItem]:
    if isinstance(file_obj, bytes):
        file_obj = io.BytesIO(file_obj)
    root = DefusedET.parse(file_obj).getroot()
    findings: list[VulnerabilityItem] = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        target = address.get("addr") if address is not None else "unknown"
        for port in host.findall("ports/port"):
            if port.find("state[@state='open']") is None:
                continue
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            protocol, port_id = port.get("protocol", "tcp"), port.get("portid", "unknown")
            details = []
            if service is not None:
                details.append(" ".join(filter(None, [service.get("product"), service.get("version"), service.get("extrainfo")])))
            for script in port.findall("script"):
                details.append(f"{script.get('id', 'nse')}: {script.get('output', '')}")
            severity = Severity.MEDIUM if service_name in {"telnet", "ftp", "microsoft-ds", "netbios-ssn"} else Severity.LOW
            findings.append(VulnerabilityItem(title=f"Open {service_name} service", tool_source="Nmap", severity=severity, target_url=f"{protocol}://{target}:{port_id}", raw_evidence="\n".join(part for part in details if part) or f"Nmap reported open {service_name} on port {port_id}."))
    return findings
