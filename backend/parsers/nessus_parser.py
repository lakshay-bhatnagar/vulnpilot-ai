"""Parser for Nessus .nessus XML exports."""

import io
import re
from typing import BinaryIO

from defusedxml import ElementTree as DefusedET

from backend.models.schemas import Severity, VulnerabilityItem

RISK_TO_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.LOW,
    "informational": Severity.LOW,
}


def _text(item, tag: str) -> str | None:
    value = item.findtext(tag)
    return value.strip() if value and value.strip() else None


def _severity(item) -> Severity:
    risk = _text(item, "risk_factor")
    if risk:
        return RISK_TO_SEVERITY.get(risk.lower(), Severity.MEDIUM)

    numeric = item.get("severity", "2")
    return {"4": Severity.CRITICAL, "3": Severity.HIGH, "2": Severity.MEDIUM}.get(
        numeric, Severity.LOW
    )


def _target(host: str, item) -> str:
    port = item.get("port", "0")
    protocol = item.get("protocol", "tcp")
    return f"{protocol}://{host}:{port}"


def _cwe(item) -> str | None:
    for tag in ("cwe", "cwe_id"):
        value = _text(item, tag)
        if value:
            match = re.search(r"CWE-(\d+)", value, re.IGNORECASE)
            if match:
                return f"CWE-{match.group(1)}"
    return None


def _evidence(item) -> str | None:
    fields = (
        ("Plugin ID", item.get("pluginID")),
        ("CVSS", _text(item, "cvss3_base_score") or _text(item, "cvss_base_score")),
        ("CVE", _text(item, "cve")),
        ("Synopsis", _text(item, "synopsis")),
        ("Description", _text(item, "description")),
        ("Plugin Output", _text(item, "plugin_output")),
        ("References", _text(item, "see_also")),
    )
    parts = [f"{label}: {value}" for label, value in fields if value]
    return "\n\n".join(parts) or None


def parse_nessus_xml(file_obj: BinaryIO | bytes) -> list[VulnerabilityItem]:
    """Convert Nessus ReportItems to VulnPilot's normalized finding model."""
    if isinstance(file_obj, bytes):
        file_obj = io.BytesIO(file_obj)

    root = DefusedET.parse(file_obj).getroot()
    findings: list[VulnerabilityItem] = []
    for report_host in root.findall(".//ReportHost"):
        host = report_host.get("name") or "unknown"
        host_ip = _text(report_host, "HostProperties/tag[@name='host-ip']")
        host = host_ip or host

        for item in report_host.findall("ReportItem"):
            plugin_id = item.get("pluginID", "unknown")
            plugin_name = item.get("pluginName") or "Untitled Nessus Finding"
            findings.append(
                VulnerabilityItem(
                    title=f"{plugin_name} (Nessus Plugin {plugin_id})",
                    tool_source="Nessus",
                    severity=_severity(item),
                    target_url=_target(host, item),
                    cwe=_cwe(item),
                    cve=_text(item, "cve"),
                    cvss=_text(item, "cvss3_base_score") or _text(item, "cvss_base_score"),
                    raw_evidence=_evidence(item),
                    remediation=_text(item, "solution"),
                    generated_poc=None,
                    references=[_text(item, "see_also")] if _text(item, "see_also") else [],
                )
            )
    return findings
