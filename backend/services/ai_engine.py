"""OpenRouter-backed enrichment and deduplication for scanner findings with automatic model fallbacks."""

import json
import re
from collections.abc import Sequence
from time import perf_counter

import httpx
from pydantic import ValidationError

from backend.config import get_settings
from backend.models.schemas import (
    ScanAnalysisResponse,
    ScanAnalysisMetadata,
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
    "target_url": "string", "cwe": "CWE-N", "cve": "CVE-N|null", "cvss": "number|string|null", "owasp_category": "Axx:2021 - name",
    "raw_evidence": "string|null", "request_payload": "string|null",
    "generated_poc": "string|null", "remediation": "string|null",
    "secure_code_fix": "string|null", "mitre_attack": "string|null", "capec": "CAPEC-N|null", "references": ["string"],
    "package_name": "string|null", "installed_version": "string|null", "fixed_version": "string|null", "exploitability": "string|null", "affected_file": "string|null"
  }],
  "summary": {
    "total_raw_findings": 0, "unique_findings": 0, "deduplicated_count": 0,
    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "tools_detected": ["string"]
  }
}

Deduplicate findings that share the same normalized endpoint and root vulnerability class,
while retaining useful evidence from all duplicates. Map each retained finding to OWASP Top 10
(2021), an appropriate CWE ID, MITRE ATT&CK technique, and CAPEC attack pattern. Provide a realistic, minimally scoped proof-of-concept payload
for authorized testing and a secure code fix snippet. Never invent endpoints or claim a finding
was verified when the scanner evidence does not support it. Preserve scanner severity unless
there is clear evidence it is wrong. For dependency findings, preserve package name, installed/fixed versions,
affected manifest file, exploitability evidence, CVE, CVSS, and upgrade recommendation."""

HISTORICAL_CONTEXT_INSTRUCTION = """When historical_context is present, use the prior findings and prior risk score to
prioritize recurring risk in remediation language. Do not fabricate historical findings; the
application performs authoritative new/resolved/recurring classification after your response."""


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
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OpenRouter returned an invalid JSON analysis response.") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("OpenRouter returned an analysis response with an invalid shape.")
    return parsed


async def process_vulnerabilities(
    findings: list[VulnerabilityItem], historical_context: dict[str, object] | None = None,
) -> ScanAnalysisResponse:
    """Ask OpenRouter to enrich parsed findings, automatically failing over across free models if rate-limited."""
    settings = get_settings()
    processing_started = perf_counter()
    if not settings.openrouter_api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured. Add it to backend/.env before uploading a scan."
        )

    raw_count = len(findings)
    scanner_payload = [finding.model_dump(mode="json") for finding in findings]
    
    # Validated OpenRouter free model slugs
    candidate_models = [
    settings.openrouter_model,
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "openai/gpt-oss-20b:free",
    "google/gemma-4-26b-a4b-it:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    ] 
    # Remove duplicates while preserving list order
    fallback_models = list(dict.fromkeys(candidate_models))

    headers = {
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:5173",
        "X-Title": "VulnPilot AI",
    }

    last_exception = None

    async with httpx.AsyncClient(timeout=httpx.Timeout(90.0)) as client:
        for model in fallback_models:
            request_payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": f"{SYSTEM_PROMPT}\n\n{HISTORICAL_CONTEXT_INSTRUCTION}"},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {"findings": scanner_payload, "historical_context": historical_context or {}},
                            ensure_ascii=False,
                        ),
                    },
                ],
                "temperature": 0.1,
            }

            try:
                print(f"[OpenRouter] Requesting analysis using model: {model}")
                response = await client.post(
                    OPENROUTER_COMPLETIONS_URL,
                    headers=headers,
                    json=request_payload,
                )
                
                if response.status_code != 200:
                    print(f"[OpenRouter] Model '{model}' responded with HTTP {response.status_code}: {response.text[:200]}")
                
                response.raise_for_status()

                completion = response.json()
                content = completion["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise TypeError("Completion content was not text")

                analysis = ScanAnalysisResponse.model_validate(_extract_json(content))
                print(f"[OpenRouter] Successfully processed scan using: {model}")
                return analysis.model_copy(
                    update={
                        "summary": _build_summary(raw_count, analysis.findings),
                        "analysis_metadata": ScanAnalysisMetadata(
                            ai_provider="OpenRouter",
                            ai_model=model,
                            processing_duration_ms=round((perf_counter() - processing_started) * 1000),
                        ),
                    }
                )

            except Exception as exc:
                print(f"[OpenRouter] Model '{model}' failed ({type(exc).__name__}). Trying next fallback model...")
                last_exception = exc
                continue

    raise RuntimeError(
        f"All OpenRouter fallback models failed or were rate-limited. Last error: {last_exception}"
    )
