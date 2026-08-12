"""Small parsers for scanners that do not yet have legacy parser modules."""

from __future__ import annotations

import json
from typing import Any

from backend.models.schemas import Severity, VulnerabilityItem


def _severity(value: object) -> Severity:
    value = str(value or "Low").lower()
    return Severity.CRITICAL if value == "critical" else Severity.HIGH if value == "high" else Severity.MEDIUM if value in {"medium", "moderate"} else Severity.LOW


def _as_list(value: object) -> list[dict[str, Any]]:
    return value if isinstance(value, list) else []


def parse_dependency_check_json(content: bytes) -> list[VulnerabilityItem]:
    report = json.loads(content.decode("utf-8"))
    findings: list[VulnerabilityItem] = []
    for dependency in _as_list(report.get("dependencies") if isinstance(report, dict) else None):
        for vulnerability in _as_list(dependency.get("vulnerabilities")):
            cve = vulnerability.get("name") or vulnerability.get("source")
            findings.append(VulnerabilityItem(title=f"Vulnerable dependency: {dependency.get('fileName', 'unknown')}", tool_source="Dependency-Check", severity=_severity(vulnerability.get("severity")), target_url=str(dependency.get("filePath") or dependency.get("fileName") or "dependency"), cve=str(cve) if cve else None, cvss=str(vulnerability.get("cvssv3", {}).get("baseScore") or vulnerability.get("cvssv2", {}).get("score") or "") or None, raw_evidence=str(vulnerability.get("description") or "Dependency-Check vulnerability match."), package_name=str(dependency.get("fileName") or "") or None, affected_file=str(dependency.get("filePath") or "") or None))
    return findings


def parse_grype_json(content: bytes) -> list[VulnerabilityItem]:
    report = json.loads(content.decode("utf-8"))
    findings: list[VulnerabilityItem] = []
    for match in _as_list(report.get("matches") if isinstance(report, dict) else None):
        vulnerability, artifact = match.get("vulnerability", {}), match.get("artifact", {})
        findings.append(VulnerabilityItem(title=f"{vulnerability.get('id', 'Unknown CVE')} in {artifact.get('name', 'package')}", tool_source="Grype", severity=_severity(vulnerability.get("severity")), target_url=str(artifact.get("locations", [{}])[0].get("path") if artifact.get("locations") else artifact.get("name") or "dependency"), cve=str(vulnerability.get("id") or "") or None, cvss=str((vulnerability.get("cvss") or [{}])[0].get("metrics", {}).get("baseScore") or "") or None, raw_evidence=str(vulnerability.get("description") or "Grype vulnerability match."), package_name=str(artifact.get("name") or "") or None, installed_version=str(artifact.get("version") or "") or None, fixed_version=str((vulnerability.get("fix", {}) or {}).get("versions", [""])[0]) or None))
    return findings


def parse_gitleaks_json(content: bytes) -> list[VulnerabilityItem]:
    findings: list[VulnerabilityItem] = []
    for leak in _as_list(json.loads(content.decode("utf-8"))):
        findings.append(VulnerabilityItem(title=f"Exposed secret: {leak.get('RuleID', 'Gitleaks finding')}", tool_source="Gitleaks", severity=Severity.HIGH, target_url=f"{leak.get('File', 'source')}:{leak.get('StartLine', '')}", cwe="CWE-798", raw_evidence=str(leak.get("Description") or leak.get("Match") or "Gitleaks detected a secret."), affected_file=str(leak.get("File") or "") or None, remediation="Revoke the exposed secret, remove it from source control, and store replacement credentials in a secret manager."))
    return findings
