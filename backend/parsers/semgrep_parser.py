"""Normalize Semgrep JSON into VulnPilot vulnerability items."""

from __future__ import annotations

import json
from typing import Any

from backend.models.schemas import Severity, VulnerabilityItem


def _severity(result: dict[str, Any]) -> Severity:
    extra = result.get("extra") or {}
    value = str((extra.get("metadata") or {}).get("impact") or extra.get("severity") or result.get("severity") or "warning").lower()
    if value in {"critical"}:
        return Severity.CRITICAL
    if value in {"high", "error"}:
        return Severity.HIGH
    if value in {"medium", "warning"}:
        return Severity.MEDIUM
    return Severity.LOW


def _first(value: object) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None


def parse_semgrep_json(content: bytes) -> list[VulnerabilityItem]:
    try:
        payload = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError("Semgrep did not produce valid JSON output.") from exc
    findings: list[VulnerabilityItem] = []
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = str(result.get("path") or "unknown")
        line = int((result.get("start") or {}).get("line") or 0)
        message = str(extra.get("message") or result.get("check_id") or "Semgrep finding")
        references = metadata.get("references") or []
        if isinstance(references, str):
            references = [references]
        findings.append(VulnerabilityItem(
            title=str(metadata.get("shortlink") or result.get("check_id") or message),
            tool_source="Semgrep",
            severity=_severity(result),
            target_url=f"file://{path}{f'#L{line}' if line else ''}",
            cwe=_first(metadata.get("cwe") or metadata.get("cwe_id")),
            owasp_category=_first(metadata.get("owasp") or metadata.get("owasp-top-ten")),
            raw_evidence=f"{message}\n\nFile: {path}{f', line {line}' if line else ''}\n\n{extra.get('lines', '')}".strip(),
            remediation=_first(metadata.get("remediation") or metadata.get("recommendation")),
            secure_code_fix=str(extra["fix"]) if extra.get("fix") else None,
            references=[str(reference) for reference in references],
        ))
    return findings
