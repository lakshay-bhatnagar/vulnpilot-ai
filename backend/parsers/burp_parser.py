import base64
import io
import re
from typing import BinaryIO

from defusedxml import ElementTree as DefusedET

from backend.models.schemas import Severity, VulnerabilityItem

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.LOW,
    "info": Severity.LOW,
}


def _decode_burp_payload(element) -> str | None:
    if element is None or element.text is None:
        return None

    raw = element.text.strip()
    if not raw:
        return None

    is_base64 = element.get("base64", "false").lower() == "true"
    if is_base64:
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return raw

    return raw


def _normalize_severity(value: str | None) -> Severity:
    if not value:
        return Severity.MEDIUM
    return SEVERITY_MAP.get(value.strip().lower(), Severity.MEDIUM)


def _build_target_url(host: str | None, path: str | None) -> str:
    host = (host or "").strip()
    path = (path or "").strip()

    if host and path:
        if path.startswith("/"):
            return f"{host.rstrip('/')}{path}"
        return f"{host.rstrip('/')}/{path}"

    return host or path or "unknown"


def _extract_cwe(issue) -> str | None:
    for tag in ("cwe", "vulnerabilityClassifications"):
        element = issue.find(tag)
        if element is not None and element.text:
            match = re.search(r"CWE-\d+", element.text, re.IGNORECASE)
            if match:
                return match.group(0).upper()
    return None


def parse_burp_xml(file_obj: BinaryIO | bytes) -> list[VulnerabilityItem]:
    """Parse a Burp Suite XML export into VulnerabilityItem objects."""
    if isinstance(file_obj, bytes):
        file_obj = io.BytesIO(file_obj)

    tree = DefusedET.parse(file_obj)
    root = tree.getroot()

    findings: list[VulnerabilityItem] = []

    for issue in root.findall(".//issue"):
        title = (issue.findtext("name") or issue.findtext("type") or "Untitled Burp Issue").strip()
        severity = _normalize_severity(issue.findtext("severity"))
        target_url = _build_target_url(issue.findtext("host"), issue.findtext("path"))

        request = _decode_burp_payload(issue.find("request"))
        response = _decode_burp_payload(issue.find("response"))

        evidence_parts: list[str] = []
        if issue.findtext("issueDetail"):
            evidence_parts.append(issue.findtext("issueDetail", default="").strip())
        if issue.findtext("issueBackground"):
            evidence_parts.append(issue.findtext("issueBackground", default="").strip())
        if response:
            evidence_parts.append(f"--- Response ---\n{response[:4000]}")

        raw_evidence = "\n\n".join(part for part in evidence_parts if part) or None

        findings.append(
            VulnerabilityItem(
                title=title,
                tool_source="Burp Suite",
                severity=severity,
                target_url=target_url,
                cwe=_extract_cwe(issue),
                owasp_category=None,
                raw_evidence=raw_evidence,
                request_payload=request,
                generated_poc=None,
                remediation=issue.findtext("remediationDetail") or issue.findtext("remediationBackground"),
            )
        )

    return findings
