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

  const endpoint = `${API_BASE_URL}/api/v1/scan/upload`;
  console.debug("[VulnPilot upload] request start", {
    endpoint,
    origin: window.location.origin,
    file: { name: file.name, size: file.size, type: file.type },
  });

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
    });

    console.debug("[VulnPilot upload] HTTP response", {
      status: response.status,
      ok: response.ok,
      headers: Object.fromEntries(response.headers.entries()),
    });

    // Read once so diagnostics do not accidentally consume the response body twice.
    const rawBody = await response.text();
    console.debug("[VulnPilot upload] raw response body", rawBody);

    let body: ScanAnalysisResponse | { detail?: string | { msg?: string }[] };
    try {
      body = JSON.parse(rawBody) as ScanAnalysisResponse | { detail?: string | { msg?: string }[] };
    } catch (error) {
      console.error("[VulnPilot upload] response JSON parse failed", error);
      throw new Error("The scan API returned an invalid JSON response.");
    }

    console.debug("[VulnPilot upload] parsed response", body);

    if (!response.ok) {
      let message = `Upload failed (${response.status})`;
      if (typeof body.detail === "string") {
        message = body.detail;
      } else if (Array.isArray(body.detail) && body.detail[0]?.msg) {
        message = body.detail[0].msg;
      }
      throw new Error(message);
    }

    return body as ScanAnalysisResponse;
  } catch (error) {
    console.error("[VulnPilot upload] request failed", error);
    throw error;
  }
}
