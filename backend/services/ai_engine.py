"""Mock AI enrichment pipeline for vulnerability findings."""

from urllib.parse import urlparse

from backend.models.schemas import (
    ScanAnalysisResponse,
    ScanSummaryMetrics,
    Severity,
    SeverityBreakdown,
    VulnerabilityItem,
)

# Title keyword → (CWE, OWASP, MITRE ATT&CK, remediation template)
ENRICHMENT_RULES: list[tuple[tuple[str, ...], dict[str, str]]] = [
    (
        ("sql injection", "sqli", "sql-injection"),
        {
            "cwe": "CWE-89",
            "owasp_category": "A03:2021 - Injection",
            "mitre_attack": "T1190",
            "remediation": (
                "Use parameterised queries or prepared statements for all database access. "
                "Apply strict input validation and least-privilege DB accounts."
            ),
        },
    ),
    (
        ("cross-site scripting", "xss", "reflected xss", "stored xss"),
        {
            "cwe": "CWE-79",
            "owasp_category": "A03:2021 - Injection",
            "mitre_attack": "T1059.007",
            "remediation": (
                "Encode all user-controlled output in the appropriate context (HTML, JS, URL). "
                "Deploy a strict Content-Security-Policy and validate input server-side."
            ),
        },
    ),
    (
        ("ssrf", "server-side request forgery"),
        {
            "cwe": "CWE-918",
            "owasp_category": "A10:2021 - Server-Side Request Forgery",
            "mitre_attack": "T1190",
            "remediation": (
                "Block outbound requests to internal/metadata IP ranges. "
                "Use an allowlist of permitted destinations and disable URL redirects in fetchers."
            ),
        },
    ),
    (
        ("path traversal", "directory traversal", "lfi", "local file inclusion"),
        {
            "cwe": "CWE-22",
            "owasp_category": "A01:2021 - Broken Access Control",
            "mitre_attack": "T1083",
            "remediation": (
                "Normalise and validate file paths; reject '../' sequences. "
                "Serve files from a chrooted directory with indirect object references."
            ),
        },
    ),
    (
        ("authentication", "auth bypass", "broken auth", "jwt", "session"),
        {
            "cwe": "CWE-287",
            "owasp_category": "A07:2021 - Identification and Authentication Failures",
            "mitre_attack": "T1556",
            "remediation": (
                "Enforce strong session management, MFA for sensitive actions, and "
                "cryptographic verification of tokens on every protected endpoint."
            ),
        },
    ),
    (
        ("access control", "idor", "authorization", "privilege"),
        {
            "cwe": "CWE-639",
            "owasp_category": "A01:2021 - Broken Access Control",
            "mitre_attack": "T1068",
            "remediation": (
                "Implement server-side authorisation checks on every object reference. "
                "Derive tenant/user scope from the authenticated session, never from client input."
            ),
        },
    ),
    (
        ("misconfiguration", "default credential", "debug", "verbose error"),
        {
            "cwe": "CWE-16",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "mitre_attack": "T1592",
            "remediation": (
                "Harden default configurations, disable debug endpoints in production, "
                "and automate configuration drift detection in CI/CD."
            ),
        },
    ),
]

DEFAULT_ENRICHMENT = {
    "cwe": "CWE-693",
    "owasp_category": "A05:2021 - Security Misconfiguration",
    "mitre_attack": "T1190",
    "remediation": (
        "Review the finding in context of the affected endpoint, confirm exploitability, "
        "and apply defence-in-depth controls (validation, authz, logging, and patching)."
    ),
}

SEVERITY_POC_TEMPLATES: dict[Severity, str] = {
    Severity.CRITICAL: "# Critical — validate exploitability in a staging mirror before production retest\n",
    Severity.HIGH: "# High — reproduce with an authenticated session and capture evidence\n",
    Severity.MEDIUM: "# Medium — confirm impact with a minimal proof-of-concept request\n",
    Severity.LOW: "# Low — document the observation and verify during the next hardening sprint\n",
}


def _normalize_dedup_key(item: VulnerabilityItem) -> str:
    parsed = urlparse(item.target_url)
    host = (parsed.netloc or item.target_url).lower()
    path = (parsed.path or "/").rstrip("/") or "/"
    title = item.title.strip().lower()
    return f"{title}|{host}{path}|{item.severity.value}"


def _lookup_enrichment(title: str) -> dict[str, str]:
    lowered = title.lower()
    for keywords, mapping in ENRICHMENT_RULES:
        if any(keyword in lowered for keyword in keywords):
            return mapping
    return DEFAULT_ENRICHMENT


def _generate_poc(item: VulnerabilityItem) -> str:
    if item.generated_poc:
        return item.generated_poc

    header = SEVERITY_POC_TEMPLATES.get(item.severity, "")
    if item.request_payload:
        return f"{header}# Replay captured request against {item.target_url}\n{item.request_payload}"

    return (
        f"{header}# Automated PoC stub for: {item.title}\n"
        f"curl -i '{item.target_url}'"
    )


def _enrich_item(item: VulnerabilityItem) -> VulnerabilityItem:
    mapping = _lookup_enrichment(item.title)

    return item.model_copy(
        update={
            "cwe": item.cwe or mapping["cwe"],
            "owasp_category": item.owasp_category or mapping["owasp_category"],
            "mitre_attack": item.mitre_attack or mapping["mitre_attack"],
            "remediation": item.remediation or mapping["remediation"],
            "generated_poc": _generate_poc(item),
        }
    )


def _build_summary(
    raw_count: int,
    unique_findings: list[VulnerabilityItem],
) -> ScanSummaryMetrics:
    breakdown = SeverityBreakdown()
    tools: set[str] = set()

    for item in unique_findings:
        tools.add(item.tool_source)
        if item.severity == Severity.CRITICAL:
            breakdown.critical += 1
        elif item.severity == Severity.HIGH:
            breakdown.high += 1
        elif item.severity == Severity.MEDIUM:
            breakdown.medium += 1
        else:
            breakdown.low += 1

    return ScanSummaryMetrics(
        total_raw_findings=raw_count,
        unique_findings=len(unique_findings),
        deduplicated_count=max(0, raw_count - len(unique_findings)),
        severity_breakdown=breakdown,
        tools_detected=sorted(tools),
    )


def process_vulnerabilities(findings: list[VulnerabilityItem]) -> ScanAnalysisResponse:
    """
    Mock AI pipeline: deduplicate findings and attach CWE, MITRE ATT&CK, and remediation data.
    """
    raw_count = len(findings)
    deduped: dict[str, VulnerabilityItem] = {}

    for finding in findings:
        key = _normalize_dedup_key(finding)
        if key not in deduped:
            deduped[key] = finding
            continue

        existing = deduped[key]
        merged_evidence = "\n\n--- Duplicate evidence ---\n".join(
            part for part in (existing.raw_evidence, finding.raw_evidence) if part
        )
        deduped[key] = existing.model_copy(
            update={
                "raw_evidence": merged_evidence or existing.raw_evidence,
                "request_payload": existing.request_payload or finding.request_payload,
            }
        )

    enriched = [_enrich_item(item) for item in deduped.values()]
    enriched.sort(
        key=lambda item: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[item.severity.value],
            item.title.lower(),
        )
    )

    return ScanAnalysisResponse(
        findings=enriched,
        summary=_build_summary(raw_count, enriched),
    )
