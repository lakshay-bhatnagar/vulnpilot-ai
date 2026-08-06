const API_BASE_URL = "http://localhost:8000";

export type ApiSeverity = "Critical" | "High" | "Medium" | "Low";

export type ApiVulnerabilityItem = {
  title: string;
  tool_source: string;
  severity: ApiSeverity;
  target_url: string;
  cwe?: string | null;
  cve?: string | null;
  cvss?: string | null;
  owasp_category?: string | null;
  raw_evidence?: string | null;
  request_payload?: string | null;
  generated_poc?: string | null;
  remediation?: string | null;
  secure_code_fix?: string | null;
  capec?: string | null;
  mitre_attack?: string | null;
  package_name?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  exploitability?: string | null;
  affected_file?: string | null;
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

export type ScanAnalysisMetadata = {
  detected_scanner: string | null;
  ai_provider: string;
  ai_model: string | null;
  processing_duration_ms: number | null;
  historical_summary?: { new_findings: number; resolved_findings: number; recurring_findings: number; risk_trend: string } | null;
};

export type ScanAnalysisResponse = {
  findings: ApiVulnerabilityItem[];
  summary: ApiScanSummaryMetrics;
  analysis_metadata?: ScanAnalysisMetadata | null;
};

export type ScannerName = "nmap" | "nuclei" | "mobsf";
export type ScanProfile =
  | "external_attack_surface"
  | "web_application_assessment"
  | "infrastructure_assessment"
  | "mobile_assessment"
  | "source_code_assessment"
  | "software_composition_analysis"
  | "custom_scan";
export type ProfileMode = "quick" | "standard" | "comprehensive";
export type ScanJobStatus =
  | "Queued"
  | "Running"
  | "Parsing"
  | "AI Analysis"
  | "Generating Report"
  | "Completed"
  | "Failed"
  | "Cancelled";

export type CreateScanJobRequest = {
  scanner: ScannerName;
  target: string;
  scan_type: string;
  depth: "shallow" | "standard" | "deep";
  scan_profile?: ScanProfile;
  profile_mode?: ProfileMode;
  generate_executive_report: boolean;
  custom_args: string[];
  project_id?: string;
};

export type ScanToolResult = {
  scanner: string;
  status: "Running" | "Completed" | "Skipped" | "Failed";
  finding_count: number;
  raw_output_path: string | null;
  error_message: string | null;
};

export type ScanJob = {
  job_id: string;
  scanner: string;
  target: string;
  scan_type: string;
  project_id: string | null;
  status: ScanJobStatus;
  progress: number;
  current_phase: string;
  current_scanner: string | null;
  created_time: string;
  started_time: string | null;
  completed_time: string | null;
  duration: number | null;
  finding_count: number;
  error_message: string | null;
  raw_output_path: string | null;
  normalized_output_path: string | null;
  ai_output_path: string | null;
  report_path: string | null;
  scan_profile: ScanProfile | null;
  profile_mode: ProfileMode | null;
  tool_results: ScanToolResult[];
  source_type: string | null;
  detected_languages: string[];
  mobile_type: string | null;
  analysis: ScanAnalysisResponse | null;
};

export async function createMobileScanJob({ file, profileMode, generateExecutiveReport, projectId }: { file: File; profileMode: ProfileMode; generateExecutiveReport: boolean; projectId?: string }): Promise<ScanJob> {
  const body = new FormData();
  body.append("file", file);
  body.append("profile_mode", profileMode);
  body.append("generate_executive_report", String(generateExecutiveReport));
  if (projectId) body.append("project_id", projectId);
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/mobile`, { method: "POST", body });
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ScanJob;
}

export type ReportMetadata = {
  company_name: string;
  assessment_date: string;
  assessment_scope: string;
  assessment_type: string;
  classification: string;
};

async function readApiError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: string };
    return body.detail || `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

export async function generateExecutiveReport(metadata: ReportMetadata): Promise<Blob> {
  const response = await fetch(`${API_BASE_URL}/api/v1/report/regenerate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ metadata }),
  });
  if (!response.ok) throw new Error(await readApiError(response));
  return response.blob();
}

export async function generateProjectExecutiveReport(projectId: string, sessionId: string, metadata: ReportMetadata): Promise<Blob> {
  const query = new URLSearchParams({ project_id: projectId, session_id: sessionId });
  const response = await fetch(`${API_BASE_URL}/api/v1/report/regenerate?${query}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ metadata }),
  });
  if (!response.ok) throw new Error(await readApiError(response));
  return response.blob();
}

export function projectReportPreviewUrl(projectId: string, sessionId: string): string {
  return `${API_BASE_URL}/api/v1/report/preview?${new URLSearchParams({ project_id: projectId, session_id: sessionId })}`;
}

export async function createScanJob(request: CreateScanJobRequest): Promise<ScanJob> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ScanJob;
}

export type ProjectAsset = { id: string; asset_type: "domain" | "ip" | "cidr" | "repository" | "apk" | "ipa"; value: string; created_at: string };
export type ProjectScanSession = { id: string; scan_job_id: string | null; scan_type: string; target: string; status: string; created_at: string; completed_at: string | null; risk_score: number; normalized_path: string | null; ai_path: string | null; report_path: string | null };
export type Project = { id: string; name: string; description: string; created_at: string; updated_at: string; assets: ProjectAsset[]; scan_history: ProjectScanSession[]; risk_score: number; trend: string; open_findings: number; resolved_findings: number };

export async function listProjects(): Promise<Project[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/projects`);
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as Project[];
}

export async function createProject(name: string, description: string): Promise<Project> {
  const response = await fetch(`${API_BASE_URL}/api/v1/projects`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, description }) });
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as Project;
}

export async function addProjectAsset(projectId: string, assetType: ProjectAsset["asset_type"], value: string): Promise<ProjectAsset> {
  const response = await fetch(`${API_BASE_URL}/api/v1/projects/${encodeURIComponent(projectId)}/assets`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ asset_type: assetType, value }) });
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ProjectAsset;
}

export async function createSourceCodeScanJob({
  archive,
  sourceLocation,
  profileMode,
  generateExecutiveReport,
  projectId,
}: {
  archive: File | null;
  sourceLocation: string;
  profileMode: ProfileMode;
  generateExecutiveReport: boolean;
  projectId?: string;
}): Promise<ScanJob> {
  const body = new FormData();
  if (archive) body.append("file", archive);
  else if (/^(https?|ssh):\/\//i.test(sourceLocation) || sourceLocation.startsWith("git@")) body.append("repository_url", sourceLocation);
  else body.append("local_path", sourceLocation);
  body.append("profile_mode", profileMode);
  body.append("generate_executive_report", String(generateExecutiveReport));
  if (projectId) body.append("project_id", projectId);
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/source-code`, { method: "POST", body });
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ScanJob;
}

export async function createDependencyScanJob({
  archive,
  sourceLocation,
  profileMode,
  generateExecutiveReport,
  projectId,
}: {
  archive: File | null;
  sourceLocation: string;
  profileMode: ProfileMode;
  generateExecutiveReport: boolean;
  projectId?: string;
}): Promise<ScanJob> {
  const body = new FormData();
  if (archive) body.append("file", archive);
  else if (/^(https?|ssh):\/\//i.test(sourceLocation) || sourceLocation.startsWith("git@")) body.append("repository_url", sourceLocation);
  else body.append("local_path", sourceLocation);
  body.append("profile_mode", profileMode);
  body.append("generate_executive_report", String(generateExecutiveReport));
  if (projectId) body.append("project_id", projectId);
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/dependency`, { method: "POST", body });
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ScanJob;
}

export async function getScanJob(jobId: string): Promise<ScanJob> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${jobId}`);
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ScanJob;
}

export function getScanJobEventsUrl(jobId: string): string {
  return `${API_BASE_URL}/api/v1/scans/${encodeURIComponent(jobId)}/events`;
}

export async function getScanAnalysis(jobId: string): Promise<ScanAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${jobId}/analysis`);
  if (!response.ok) throw new Error(await readApiError(response));
  return (await response.json()) as ScanAnalysisResponse;
}

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
