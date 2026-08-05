import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { DropzoneCard } from "@/components/upload/dropzone-card";
import { AnalysisPipelineCard } from "@/components/upload/analysis-pipeline-card";
import { ScanConfigBar } from "@/components/upload/scan-config-bar";
import { useScan } from "@/lib/scan-context";

export const Route = createFileRoute("/upload")({
  component: UploadPage,
  head: () => ({
    meta: [
      { title: "File Upload & Scan | VulnPilot AI" },
      { name: "description", content: "Upload and scan files with VulnPilot AI" },
      { property: "og:title", content: "File Upload & Scan | VulnPilot AI" },
      { property: "og:description", content: "Upload and scan files with VulnPilot AI" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function UploadPage() {
  const navigate = useNavigate();
  const { uploadFilesBatch, isLoading } = useScan();

  const handleFilesSelected = async (files: File[]) => {
    const success = await uploadFilesBatch(files);
    if (success) {
      navigate({ to: "/vulnerabilities" });
    }
  };

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">File Upload & Scan</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Ingest scanner artifacts and let the AI copilot normalise, deduplicate and
          prioritise findings.
        </p>
      </div>
      <ScanConfigBar disabled={isLoading} onStartAnalysis={() => navigate({ to: "/vulnerabilities" })} />
      <DropzoneCard onFilesSelected={handleFilesSelected} disabled={isLoading} />
      <AnalysisPipelineCard />
    </div>
  );
}
