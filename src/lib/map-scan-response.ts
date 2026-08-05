import type { ScanAnalysisResponse, ApiVulnerabilityItem } from "@/lib/scan-api";
import type { DashboardMetrics, Finding, Severity } from "@/lib/vulnerability-data";

const SEVERITY_TO_CVSS: Record<Severity, number> = {
  critical: 9.1,
  high: 7.5,
  medium: 5.5,
  low: 3.1,
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 7.5,
  medium: 5,
  low: 2.5,
};

function toSeverity(value: ApiVulnerabilityItem["severity"]): Severity {
  return value.toLowerCase() as Severity;
}

function parseHttpMethod(requestPayload?: string | null): string {
  if (!requestPayload) return "GET";
  const firstLine = requestPayload.split("\n")[0]?.trim() ?? "";
  const match = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/i);
  return match ? match[1]!.toUpperCase() : "GET";
}

function splitEvidence(rawEvidence?: string | null): { impact: string; response: string } {
  if (!rawEvidence) {
    return { impact: "No additional evidence captured by the scanner.", response: "No response body captured." };
  }

  const marker = "--- Response ---";
  if (rawEvidence.includes(marker)) {
    const [before, after] = rawEvidence.split(marker, 2);
    return {
      impact: before.trim() || "Scanner reported a confirmed vulnerability at this endpoint.",
      response: after?.trim() || "No response body captured.",
    };
  }

  return {
    impact: rawEvidence.trim(),
    response: "No response body captured.",
  };
}

function shortOwasp(owaspCategory?: string | null): string {
  if (!owaspCategory) return "A05:2021";
  const match = owaspCategory.match(/A\d{2}:\d{4}/);
  return match?.[0] ?? owaspCategory.slice(0, 8);
}

function longLabel(prefix: string, value?: string | null, fallback = "Not mapped"): string {
  if (!value) return fallback;
  if (value.includes(" - ") || value.includes(":")) return value;
  return `${prefix}${value}`;
}

export function mapApiFinding(item: ApiVulnerabilityItem, index: number): Finding {
  const severity = toSeverity(item.severity);
  const { impact, response } = splitEvidence(item.raw_evidence);
  const remediation =
    item.remediation?.trim() ||
    "Review the affected endpoint, confirm exploitability, and apply defence-in-depth controls.";

  return {
    id: `VP-${String(index + 1).padStart(4, "0")}`,
    title: item.title,
    severity,
    owasp: shortOwasp(item.owasp_category),
    owaspLong: item.owasp_category ?? "A05:2021 - Security Misconfiguration",
    cwe: item.cwe ?? "CWE-693",
    cweLong: longLabel("", item.cwe, "CWE-693: Protection Mechanism Failure"),
    mitre: item.mitre_attack ?? "T1190",
    mitreLong: longLabel("", item.mitre_attack, "T1190 - Exploit Public-Facing Application"),
    capec: "CAPEC-100",
    capecLong: "CAPEC-100 - Exploit Web Application",
    cvss: SEVERITY_TO_CVSS[severity],
    tools: [item.tool_source],
    url: item.target_url,
    method: parseHttpMethod(item.request_payload),
    firstSeen: new Date().toUTCString().replace("GMT", "UTC"),
    dedupedFrom: 1,
    impact,
    business: remediation,
    request: item.request_payload?.trim() || `${parseHttpMethod(item.request_payload)} ${item.target_url}`,
    response,
    poc: item.generated_poc?.trim() || `# PoC stub\n# Target: ${item.target_url}\ncurl -i '${item.target_url}'`,
    badCode: "# Vulnerable pattern detected by scanner — review server-side validation and authz.",
    goodCode: item.secure_code_fix?.trim() || remediation,
    execSummary: `${severityStylesLabel(severity)}: ${item.title}. ${remediation}`,
  };
}

function severityStylesLabel(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function mapApiMetrics(
  summary: ScanAnalysisResponse["summary"],
  findings: Finding[],
): DashboardMetrics {
  const severityCounts: Record<Severity, number> = {
    critical: summary.severity_breakdown.critical,
    high: summary.severity_breakdown.high,
    medium: summary.severity_breakdown.medium,
    low: summary.severity_breakdown.low,
  };

  const totalWeight =
    severityCounts.critical * SEVERITY_WEIGHT.critical +
    severityCounts.high * SEVERITY_WEIGHT.high +
    severityCounts.medium * SEVERITY_WEIGHT.medium +
    severityCounts.low * SEVERITY_WEIGHT.low;

  const count = summary.unique_findings || 1;
  const aiRiskScore = Math.min(10, Math.round((totalWeight / count) * 10) / 10);
  const aiRiskLabel =
    aiRiskScore >= 8
      ? "High Business Impact"
      : aiRiskScore >= 5.5
        ? "Moderate Business Impact"
        : "Low Business Impact";

  return {
    rawFindings: summary.total_raw_findings,
    rootCauses: summary.unique_findings,
    aiRiskScore,
    aiRiskLabel,
    severityCounts,
  };
}

export function mapScanAnalysisResponse(response: ScanAnalysisResponse, idOffset = 0): {
  findings: Finding[];
  metrics: DashboardMetrics;
  owaspCategories: string[];
  toolSources: string[];
} {
  const findings = response.findings.map((item, index) => mapApiFinding(item, idOffset + index));
  const owaspCategories = Array.from(new Set(findings.map((f) => f.owaspLong))).sort();
  const toolSources = Array.from(new Set(findings.flatMap((f) => f.tools))).sort();

  return {
    findings,
    metrics: mapApiMetrics(response.summary, findings),
    owaspCategories,
    toolSources,
  };
}

export function mergeScanResults(
  existing: {
    findings: Finding[];
    metrics: DashboardMetrics;
    owaspCategories: string[];
    toolSources: string[];
  },
  incoming: ReturnType<typeof mapScanAnalysisResponse>,
): {
  findings: Finding[];
  metrics: DashboardMetrics;
  owaspCategories: string[];
  toolSources: string[];
} {
  const findings = [...existing.findings, ...incoming.findings].map((finding, index) => ({
    ...finding,
    id: `VP-${String(index + 1).padStart(4, "0")}`,
  }));

  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
  }

  const rawFindings = existing.metrics.rawFindings + incoming.metrics.rawFindings;
  const rootCauses = findings.length;

  const mergedMetrics = mapApiMetrics(
    {
      total_raw_findings: rawFindings,
      unique_findings: rootCauses,
      deduplicated_count: Math.max(0, rawFindings - rootCauses),
      severity_breakdown: severityCounts,
      tools_detected: Array.from(
        new Set([...existing.toolSources, ...incoming.toolSources]),
      ),
    },
    findings,
  );

  return {
    findings,
    metrics: mergedMetrics,
    owaspCategories: Array.from(
      new Set([...existing.owaspCategories, ...incoming.owaspCategories]),
    ).sort(),
    toolSources: Array.from(new Set([...existing.toolSources, ...incoming.toolSources])).sort(),
  };
}
