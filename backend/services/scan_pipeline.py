"""Parser reuse, deterministic pre-AI deduplication, and artifact serialization."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from backend.models.schemas import VulnerabilityItem
from backend.parsers.mobsf_parser import parse_mobsf_json
from backend.parsers.nmap_parser import parse_nmap_xml
from backend.parsers.nuclei_parser import parse_nuclei_json
from backend.parsers.recon_parser import parse_recon_output
from backend.parsers.semgrep_parser import parse_semgrep_json
from backend.parsers.dependency_parser import parse_osv_json, parse_trivy_json


def parse_scanner_output(scanner: str, output_path: Path) -> list[VulnerabilityItem]:
    content = output_path.read_bytes()
    parsers = {"nuclei": parse_nuclei_json, "nmap": parse_nmap_xml, "mobsf": parse_mobsf_json, "semgrep": parse_semgrep_json, "trivy": parse_trivy_json, "osv-scanner": parse_osv_json, "syft": lambda _: [], "apktool": lambda _: [], "jadx": lambda _: []}
    parser = parsers.get(scanner.lower())
    if parser is not None:
        return parser(content)
    if scanner.lower() in {"subfinder", "amass", "dnsx", "httpx", "naabu", "katana", "hakrawler", "arjun"}:
        return parse_recon_output(scanner, content)
    raise ValueError(f"No output parser is configured for scanner '{scanner}'.")


def _dedup_key(finding: VulnerabilityItem) -> tuple[str, str]:
    parsed = urlparse(finding.target_url)
    endpoint = f"{parsed.netloc or finding.target_url}{parsed.path}".rstrip("/").lower()
    vulnerability_class = re.sub(r"\b(nmap|nuclei|mobsf|plugin|finding|service|open)\b|\d+", "", finding.title.lower())
    return endpoint, re.sub(r"\s+", " ", vulnerability_class).strip()


def deduplicate_findings(findings: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
    deduplicated: dict[tuple[str, str], VulnerabilityItem] = {}
    for finding in findings:
        key = _dedup_key(finding)
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = finding
            continue
        evidence_blocks = []
        if existing.raw_evidence:
            evidence_blocks.append(f"[{existing.tool_source}]\n{existing.raw_evidence}")
        if finding.raw_evidence:
            evidence_blocks.append(f"[{finding.tool_source}]\n{finding.raw_evidence}")
        evidence = "\n\n--- Correlated scanner evidence ---\n".join(evidence_blocks)
        tools = ", ".join(sorted(set((existing.tool_source + "," + finding.tool_source).split(","))))
        deduplicated[key] = existing.model_copy(update={
            "tool_source": tools,
            "raw_evidence": evidence or existing.raw_evidence,
            "request_payload": existing.request_payload or finding.request_payload,
            "cwe": existing.cwe or finding.cwe,
            "cve": existing.cve or finding.cve,
            "cvss": existing.cvss or finding.cvss,
            "remediation": existing.remediation or finding.remediation,
            "references": list(dict.fromkeys([*existing.references, *finding.references])),
        })
    return list(deduplicated.values())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
