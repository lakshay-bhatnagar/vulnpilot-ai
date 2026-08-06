"""Normalize Trivy and OSV Scanner dependency vulnerability JSON."""

from __future__ import annotations

import json
from typing import Any

from backend.models.schemas import Severity, VulnerabilityItem


SEVERITY_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _severity(value: object) -> Severity:
    return SEVERITY_MAP.get(str(value or "MEDIUM").upper(), Severity.MEDIUM)


def _cvss(record: dict[str, Any]) -> str | None:
    scores = record.get("CVSS") or record.get("cvss") or {}
    if isinstance(scores, dict):
        for score in scores.values():
            if isinstance(score, dict) and score.get("V3Score") is not None:
                return str(score["V3Score"])
            if isinstance(score, (int, float, str)):
                return str(score)
    return str(record["cvss_score"]) if record.get("cvss_score") is not None else None


def _item(record: dict[str, Any], target: str, source: str) -> VulnerabilityItem:
    package = str(record.get("PkgName") or record.get("package") or record.get("package_name") or record.get("name") or "Unknown package")
    installed = record.get("InstalledVersion") or record.get("installed_version") or record.get("version")
    fixed = record.get("FixedVersion") or record.get("fixed_version")
    cve = record.get("VulnerabilityID") or record.get("id") or record.get("cve")
    references = record.get("References") or record.get("references") or []
    if isinstance(references, str):
        references = [references]
    recommendation = f"Upgrade {package}" + (f" to {fixed}" if fixed else " to a version that resolves this advisory") + "."
    description = str(record.get("Description") or record.get("summary") or record.get("details") or "Known vulnerable dependency.")
    return VulnerabilityItem(
        title=f"{package} {installed or ''} affected by {cve or 'known advisory'}".strip(),
        tool_source=source,
        severity=_severity(record.get("Severity") or record.get("severity")),
        target_url=f"file://{target}",
        cve=str(cve) if cve else None,
        cvss=_cvss(record),
        raw_evidence=f"Package: {package}\nInstalled version: {installed or 'unknown'}\nFixed version: {fixed or 'not specified'}\nAffected file: {target}\n\n{description}",
        remediation=recommendation,
        references=[str(reference) for reference in references],
        package_name=package,
        installed_version=str(installed) if installed else None,
        fixed_version=str(fixed) if fixed else None,
        exploitability=str(record.get("Exploitability") or record.get("exploitability") or record.get("KnownExploited") or "Unknown"),
        affected_file=target,
    )


def parse_trivy_json(content: bytes) -> list[VulnerabilityItem]:
    try:
        payload = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError("Trivy did not produce valid JSON output.") from exc
    findings: list[VulnerabilityItem] = []
    for result in payload.get("Results", []):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "project manifest")
        for vulnerability in result.get("Vulnerabilities") or []:
            if isinstance(vulnerability, dict):
                findings.append(_item(vulnerability, target, "Trivy"))
    return findings


def parse_osv_json(content: bytes) -> list[VulnerabilityItem]:
    try:
        payload = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError("OSV Scanner did not produce valid JSON output.") from exc
    findings: list[VulnerabilityItem] = []
    results = payload.get("results") or payload.get("Results") or []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("source") or result.get("Source") or result.get("path") or "project manifest")
        packages = result.get("packages") or result.get("Packages") or [result]
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = package.get("package") or package.get("name")
            version = package.get("version")
            for vulnerability in package.get("vulnerabilities") or package.get("Vulnerabilities") or []:
                if not isinstance(vulnerability, dict):
                    continue
                record = {**vulnerability, "package": name, "version": version, "fixed_version": vulnerability.get("fixed_version") or vulnerability.get("fixed")}
                findings.append(_item(record, target, "OSV Scanner"))
    return findings
