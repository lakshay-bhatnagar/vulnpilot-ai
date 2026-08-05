import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { toast } from "sonner";

import { uploadScanFile } from "@/lib/scan-api";
import { mapScanAnalysisResponse, mergeScanResults } from "@/lib/map-scan-response";
import {
  emptyDashboardMetrics,
  type DashboardMetrics,
  type Finding,
} from "@/lib/vulnerability-data";

export type UploadFileStatus = "queued" | "uploading" | "complete" | "error";

export type UploadFileState = {
  id: string;
  name: string;
  sizeLabel: string;
  tool: string;
  progress: number;
  status: UploadFileStatus;
};

export type PipelineStepStatus = "complete" | "active" | "pending";

export type PipelineStep = {
  title: string;
  detail: string;
  status: PipelineStepStatus;
};

type ScanContextValue = {
  findings: Finding[];
  metrics: DashboardMetrics;
  owaspCategories: string[];
  toolSources: string[];
  uploadFiles: UploadFileState[];
  pipelineSteps: PipelineStep[];
  isLoading: boolean;
  hasScanData: boolean;
  sessionLabel: string | null;
  uploadFilesBatch: (files: File[]) => Promise<boolean>;
};

const INITIAL_PIPELINE: PipelineStep[] = [
  {
    title: "File Parsing & Schema Standardisation",
    detail: "Waiting for scan artifacts…",
    status: "pending",
  },
  {
    title: "AI Deduplication & Cross-Tool Clustering",
    detail: "Queued",
    status: "pending",
  },
  {
    title: "CWE / OWASP Top 10 / MITRE ATT&CK Mapping",
    detail: "Queued",
    status: "pending",
  },
  {
    title: "AI Prioritisation & PoC Generation",
    detail: "Queued",
    status: "pending",
  },
];

const ScanContext = createContext<ScanContextValue | null>(null);

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function inferTool(filename: string): string {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".xml")) return "Burp Suite";
  if (lower.endsWith(".json")) return "Nuclei";
  return "Scanner";
}

function isSupportedScanFile(file: File): boolean {
  const lower = file.name.toLowerCase();
  return lower.endsWith(".xml") || lower.endsWith(".json");
}

export function ScanProvider({ children }: { children: ReactNode }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [metrics, setMetrics] = useState<DashboardMetrics>(emptyDashboardMetrics);
  const [owaspCategories, setOwaspCategories] = useState<string[]>([]);
  const [toolSources, setToolSources] = useState<string[]>([]);
  const [uploadFiles, setUploadFiles] = useState<UploadFileState[]>([]);
  const [pipelineSteps, setPipelineSteps] = useState<PipelineStep[]>(INITIAL_PIPELINE);
  const [isLoading, setIsLoading] = useState(false);
  const [sessionLabel, setSessionLabel] = useState<string | null>(null);

  const hasScanData = findings.length > 0;

  const updatePipelineStep = useCallback((index: number, patch: Partial<PipelineStep>) => {
    setPipelineSteps((steps) =>
      steps.map((step, i) => (i === index ? { ...step, ...patch } : step)),
    );
  }, []);

  const updateUploadFile = useCallback((id: string, patch: Partial<UploadFileState>) => {
    setUploadFiles((files) => files.map((file) => (file.id === id ? { ...file, ...patch } : file)));
  }, []);

  const uploadFilesBatch = useCallback(
    async (files: File[]) => {
      const supported = files.filter(isSupportedScanFile);
      const unsupported = files.filter((file) => !isSupportedScanFile(file));

      if (unsupported.length > 0) {
        toast.error("Unsupported file type", {
          description: "Only Burp Suite .xml and Nuclei .json exports are supported right now.",
        });
      }

      if (supported.length === 0) {
        return false;
      }

      setSessionLabel(`vp-${crypto.randomUUID().slice(0, 6)}`);
      setIsLoading(true);
      setPipelineSteps([
        {
          title: "File Parsing & Schema Standardisation",
          detail: `Ingesting ${supported.length} file${supported.length === 1 ? "" : "s"}…`,
          status: "active",
        },
        {
          title: "AI Deduplication & Cross-Tool Clustering",
          detail: "Queued",
          status: "pending",
        },
        {
          title: "CWE / OWASP Top 10 / MITRE ATT&CK Mapping",
          detail: "Queued",
          status: "pending",
        },
        {
          title: "AI Prioritisation & PoC Generation",
          detail: "Queued",
          status: "pending",
        },
      ]);

      const queuedFiles: UploadFileState[] = supported.map((file) => ({
        id: crypto.randomUUID(),
        name: file.name,
        sizeLabel: formatFileSize(file.size),
        tool: inferTool(file.name),
        progress: 0,
        status: "queued",
      }));

      setUploadFiles(queuedFiles);

      let accumulated = {
        findings,
        metrics,
        owaspCategories,
        toolSources,
      };

      let totalRaw = 0;
      let totalUnique = 0;
      let completedUploads = 0;

      for (let index = 0; index < supported.length; index += 1) {
        const file = supported[index]!;
        const fileState = queuedFiles[index]!;

        updateUploadFile(fileState.id, { status: "uploading", progress: 15 });
        updatePipelineStep(0, {
          detail: `Parsing ${file.name}…`,
          status: "active",
        });
        updatePipelineStep(1, {
          detail: "Running AI deduplication pipeline…",
          status: "active",
        });

        try {
          updateUploadFile(fileState.id, { progress: 45 });
          const response = await uploadScanFile(file);
          updateUploadFile(fileState.id, { progress: 85 });

          const mapped = mapScanAnalysisResponse(response, accumulated.findings.length);
          accumulated = mergeScanResults(accumulated, mapped);

          totalRaw += response.summary.total_raw_findings;
          totalUnique += response.summary.unique_findings;
          completedUploads += 1;

          updateUploadFile(fileState.id, { status: "complete", progress: 100 });
        } catch (error) {
          const message = error instanceof Error ? error.message : "Upload failed";
          updateUploadFile(fileState.id, { status: "error", progress: 100 });
          toast.error(`Failed to analyze ${file.name}`, { description: message });
        }
      }

      setFindings(accumulated.findings);
      setMetrics(accumulated.metrics);
      setOwaspCategories(accumulated.owaspCategories);
      setToolSources(accumulated.toolSources);

      if (accumulated.findings.length > 0) {
        updatePipelineStep(0, {
          status: "complete",
          detail: `${completedUploads} file${completedUploads === 1 ? "" : "s"} normalised · ${totalRaw} raw findings ingested`,
        });
        updatePipelineStep(1, {
          status: "complete",
          detail: `${totalUnique} unique root causes · ${Math.max(0, totalRaw - accumulated.findings.length)} duplicates collapsed`,
        });
        updatePipelineStep(2, {
          status: "complete",
          detail: "CWE, OWASP Top 10, and MITRE ATT&CK mappings attached",
        });
        updatePipelineStep(3, {
          status: "complete",
          detail: "PoC payloads and remediation guidance generated",
        });

        toast.success("Scan analysis complete", {
          description: `${accumulated.findings.length} vulnerabilities ready on the dashboard.`,
        });
      } else {
        updatePipelineStep(0, { status: "pending", detail: "No findings parsed from upload" });
        updatePipelineStep(1, { status: "pending", detail: "Queued" });
        updatePipelineStep(2, { status: "pending", detail: "Queued" });
        updatePipelineStep(3, { status: "pending", detail: "Queued" });
      }

      setIsLoading(false);
      return accumulated.findings.length > 0;
    },
    [findings, metrics, owaspCategories, toolSources, updatePipelineStep, updateUploadFile],
  );

  const value = useMemo<ScanContextValue>(
    () => ({
      findings,
      metrics,
      owaspCategories,
      toolSources,
      uploadFiles,
      pipelineSteps,
      isLoading,
      hasScanData,
      sessionLabel,
      uploadFilesBatch,
    }),
    [
      findings,
      metrics,
      owaspCategories,
      toolSources,
      uploadFiles,
      pipelineSteps,
      isLoading,
      hasScanData,
      sessionLabel,
      uploadFilesBatch,
    ],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error("useScan must be used within a ScanProvider");
  }
  return context;
}
