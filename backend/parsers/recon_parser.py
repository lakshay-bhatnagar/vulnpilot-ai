"""Shared normalization for line and JSONL output from reconnaissance tools."""

from __future__ import annotations

import json
from collections.abc import Iterable

from backend.models.schemas import Severity, VulnerabilityItem


def _target(record: object) -> str:
    if isinstance(record, dict):
        for key in ("url", "matched-at", "host", "input", "domain", "ip"):
            value = record.get(key)
            if value:
                return str(value)
        if record.get("port") and record.get("host"):
            return f"{record['host']}:{record['port']}"
    return str(record).strip()


def _records(content: bytes) -> Iterable[object]:
    for line in content.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
            yield parsed
        except json.JSONDecodeError:
            yield stripped


def parse_recon_output(scanner: str, content: bytes) -> list[VulnerabilityItem]:
    """Normalize discovery observations without duplicating tool-specific parsers."""
    scanner_name = scanner.lower()
    labels = {
        "subfinder": "Discovered subdomain",
        "amass": "Discovered subdomain",
        "dnsx": "Resolved DNS record",
        "httpx": "Reachable HTTP service",
        "naabu": "Discovered open network service",
        "katana": "Discovered web endpoint",
        "hakrawler": "Discovered web endpoint",
        "arjun": "Discovered HTTP parameter",
    }
    title = labels.get(scanner_name, "Discovery observation")
    findings: list[VulnerabilityItem] = []
    for record in _records(content):
        target = _target(record)
        if not target or target == "None":
            continue
        evidence = json.dumps(record, ensure_ascii=False) if isinstance(record, dict) else target
        findings.append(
            VulnerabilityItem(
                title=title,
                tool_source=scanner.title() if scanner_name != "httpx" else "HTTPX",
                severity=Severity.LOW,
                target_url=target if "://" in target else f"https://{target}",
                raw_evidence=evidence[:4000],
            )
        )
    return findings
