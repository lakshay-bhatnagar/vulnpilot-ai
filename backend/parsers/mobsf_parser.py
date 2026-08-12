"""Normalize common MobSF JSON result shapes into VulnerabilityItem records."""

import json
from typing import Any, BinaryIO

from backend.models.schemas import Severity, VulnerabilityItem


def _severity(value: object) -> Severity:
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}.get(str(value).lower(), Severity.MEDIUM)


def parse_mobsf_json(file_obj: BinaryIO | bytes) -> list[VulnerabilityItem]:
    raw = file_obj if isinstance(file_obj, bytes) else file_obj.read()
    data: Any = json.loads(raw.decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        return []
    records = data.get("vulnerabilities", data.get("findings", []))
    manifest = data.get("manifest_analysis")
    if isinstance(manifest, dict):
        records = [*records if isinstance(records, list) else [], *manifest.get("manifest_findings", [])]
    code_analysis = data.get("code_analysis")
    if isinstance(code_analysis, dict):
        code_findings = code_analysis.get("findings", [])
        records = [*records if isinstance(records, list) else [], *(code_findings.values() if isinstance(code_findings, dict) else code_findings if isinstance(code_findings, list) else [])]
    if not isinstance(records, list):
        return []
    findings: list[VulnerabilityItem] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        title = str(record.get("title") or record.get("rule") or record.get("name") or record.get("issue") or "MobSF Finding")
        target = str(record.get("file") or record.get("path") or data.get("app_name", "mobile-application"))
        findings.append(VulnerabilityItem(title=title, tool_source="MobSF", severity=_severity(record.get("severity") or record.get("level") or record.get("risk")), target_url=target, cwe=str(record["cwe"]) if record.get("cwe") else None, raw_evidence=str(record.get("description") or record.get("details") or record.get("message") or "MobSF reported this mobile application finding."), remediation=str(record.get("recommendation") or record.get("solution")) if record.get("recommendation") or record.get("solution") else None))
    return findings
