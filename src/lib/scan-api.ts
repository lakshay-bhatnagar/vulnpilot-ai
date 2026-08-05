const API_BASE_URL = "http://localhost:8000";

export type ApiSeverity = "Critical" | "High" | "Medium" | "Low";

export type ApiVulnerabilityItem = {
  title: string;
  tool_source: string;
  severity: ApiSeverity;
  target_url: string;
  cwe?: string | null;
  owasp_category?: string | null;
  raw_evidence?: string | null;
  request_payload?: string | null;
  generated_poc?: string | null;
  remediation?: string | null;
  secure_code_fix?: string | null;
  mitre_attack?: string | null;
};

export type ApiSeverityBreakdown = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type ApiScanSummaryMetrics = {
  total_raw_findings: number;
  unique_findings: number;
  deduplicated_count: number;
  severity_breakdown: ApiSeverityBreakdown;
  tools_detected: string[];
};

export type ScanAnalysisResponse = {
  findings: ApiVulnerabilityItem[];
  summary: ApiScanSummaryMetrics;
};

export async function uploadScanFile(file: File): Promise<ScanAnalysisResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/v1/scan/upload`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    let message = `Upload failed (${response.status})`;
    try {
      const body = (await response.json()) as { detail?: string | { msg?: string }[] };
      if (typeof body.detail === "string") {
        message = body.detail;
      } else if (Array.isArray(body.detail) && body.detail[0]?.msg) {
        message = body.detail[0].msg;
      }
    } catch {
      // keep default message
    }
    throw new Error(message);
  }

  return (await response.json()) as ScanAnalysisResponse;
}
