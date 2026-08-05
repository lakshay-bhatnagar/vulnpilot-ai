import json
from typing import Any, BinaryIO

from backend.models.schemas import Severity, VulnerabilityItem

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.LOW,
    "unknown": Severity.MEDIUM,
}


def _normalize_severity(value: str | None) -> Severity:
    if not value:
        return Severity.MEDIUM
    return SEVERITY_MAP.get(value.strip().lower(), Severity.MEDIUM)


def _load_nuclei_records(content: str) -> list[dict[str, Any]]:
    stripped = content.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
        return records

    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


def _extract_cwe(info: dict[str, Any]) -> str | None:
    classification = info.get("classification") or {}
    cwe = classification.get("cwe-id") or classification.get("cwe_id") or info.get("cwe-id")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if cwe:
        cwe_str = str(cwe)
        return cwe_str if cwe_str.upper().startswith("CWE-") else f"CWE-{cwe_str}"
    return None


def _extract_owasp(info: dict[str, Any]) -> str | None:
    tags = info.get("tags") or []
    for tag in tags:
        if isinstance(tag, str) and ("owasp" in tag.lower() or tag.startswith("A0")):
            return tag
    classification = info.get("classification") or {}
    return classification.get("owasp") or classification.get("owasp-top-10")


def _record_to_item(record: dict[str, Any]) -> VulnerabilityItem:
    info = record.get("info") or {}
    title = info.get("name") or record.get("template-id") or record.get("templateID") or "Untitled Nuclei Finding"
    severity = _normalize_severity(info.get("severity"))
    target_url = (
        record.get("matched-at")
        or record.get("matched_at")
        or record.get("host")
        or record.get("url")
        or "unknown"
    )

    request_payload = record.get("request") or record.get("curl-command")
    if isinstance(request_payload, list):
        request_payload = "\n".join(str(item) for item in request_payload)

    evidence_parts: list[str] = []
    if info.get("description"):
        evidence_parts.append(str(info["description"]))
    if record.get("extracted-results"):
        evidence_parts.append(f"Extracted: {record['extracted-results']}")
    if record.get("matcher-name"):
        evidence_parts.append(f"Matcher: {record['matcher-name']}")
    if record.get("response"):
        response = record["response"]
        if isinstance(response, str):
            evidence_parts.append(f"--- Response ---\n{response[:4000]}")

    return VulnerabilityItem(
        title=str(title),
        tool_source="Nuclei",
        severity=severity,
        target_url=str(target_url),
        cwe=_extract_cwe(info),
        owasp_category=_extract_owasp(info),
        raw_evidence="\n\n".join(evidence_parts) or None,
        request_payload=str(request_payload) if request_payload else None,
        generated_poc=record.get("curl-command"),
        remediation=info.get("remediation") or info.get("reference"),
    )


def parse_nuclei_json(file_obj: BinaryIO | bytes) -> list[VulnerabilityItem]:
    """Parse Nuclei JSON or JSONL output into VulnerabilityItem objects."""
    if isinstance(file_obj, bytes):
        content = file_obj.decode("utf-8", errors="replace")
    else:
        raw = file_obj.read()
        content = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw

    return [_record_to_item(record) for record in _load_nuclei_records(content)]
