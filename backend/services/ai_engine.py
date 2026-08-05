"""OpenRouter-backed enrichment and deduplication for scanner findings."""

import json
import re
from collections.abc import Sequence

import httpx
from pydantic import ValidationError

from backend.config import get_settings
from backend.models.schemas import (
    ScanAnalysisResponse,
    ScanSummaryMetrics,
    Severity,
    SeverityBreakdown,
    VulnerabilityItem,
)

OPENROUTER_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """You are VulnPilot AI, an application-security analyst. Analyze only the
scanner findings supplied by the user. Return valid JSON only, with no Markdown fences or
commentary, matching this exact structure:
{
  "findings": [{
    "title": "string", "tool_source": "string", "severity": "Critical|High|Medium|Low",
    "target_url": "string", "cwe": "CWE-N", "owasp_category": "Axx:2021 - name",
    "raw_evidence": "string|null", "request_payload": "string|null",
    "generated_poc": "string|null", "remediation": "string|null",
    "secure_code_fix": "string|null", "mitre_attack": "string|null"
  }],
  "summary": {
    "total_raw_findings": 0, "unique_findings": 0, "deduplicated_count": 0,
    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "tools_detected": ["string"]
  }
}

Deduplicate findings that share the same normalized endpoint and root vulnerability class,
while retaining useful evidence from all duplicates. Map each retained finding to OWASP Top 10
(2021) and an appropriate CWE ID. Provide a realistic, minimally scoped proof-of-concept payload
for authorized testing and a secure code fix snippet. Never invent endpoints or claim a finding
was verified when the scanner evidence does not support it. Preserve scanner severity unless
there is clear evidence it is wrong."""


def _build_summary(raw_count: int, findings: Sequence[VulnerabilityItem]) -> ScanSummaryMetrics:
    breakdown = SeverityBreakdown()
    tools: set[str] = set()

    for item in findings:
        tools.add(item.tool_source)
        if item.severity is Severity.CRITICAL:
            breakdown.critical += 1
        elif item.severity is Severity.HIGH:
            breakdown.high += 1
        elif item.severity is Severity.MEDIUM:
            breakdown.medium += 1
        else:
            breakdown.low += 1

    return ScanSummaryMetrics(
        total_raw_findings=raw_count,
        unique_findings=len(findings),
        deduplicated_count=max(0, raw_count - len(findings)),
        severity_breakdown=breakdown,
        tools_detected=sorted(tools),
    )


def _extract_json(content: str) -> dict[str, object]:
    """Accept a strict JSON response and gracefully handle an accidental code fence."""
    cleaned = content.strip()
    if cleaned.startswith("```"):
        # NEW (Correct whitespace matching)
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OpenRouter returned an invalid JSON analysis response.") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("OpenRouter returned an analysis response with an invalid shape.")
    return parsed


async def process_vulnerabilities(findings: list[VulnerabilityItem]) -> ScanAnalysisResponse:
    """Ask OpenRouter to enrich parsed findings and return a validated API response."""
    settings = get_settings()
    if not settings.openrouter_api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured. Add it to backend/.env before uploading a scan."
        )

    raw_count = len(findings)
    scanner_payload = [finding.model_dump(mode="json") for finding in findings]
    request_payload = {
        "model": settings.openrouter_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps({"findings": scanner_payload}, ensure_ascii=False),
            },
        ],
        "temperature": 0.1,
        # "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:5173",
        "X-Title": "VulnPilot AI",
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0)) as client:
            response = await client.post(
                OPENROUTER_COMPLETIONS_URL,
                headers=headers,
                json=request_payload,
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:500]
        raise RuntimeError(
            f"OpenRouter analysis request failed ({exc.response.status_code}): {detail}"
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError("Unable to reach OpenRouter for scan analysis.") from exc

    try:
        completion = response.json()
        content = completion["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise TypeError("completion content was not text")
        analysis = ScanAnalysisResponse.model_validate(_extract_json(content))
    except (KeyError, IndexError, TypeError, ValidationError, RuntimeError) as exc:
        raise RuntimeError("OpenRouter returned an analysis that does not match the scan schema.") from exc

    # Metrics are computed server-side so they always match the findings sent to the UI.
    return analysis.model_copy(update={"summary": _build_summary(raw_count, analysis.findings)})
