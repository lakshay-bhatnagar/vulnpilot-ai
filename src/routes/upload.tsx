import { createFileRoute } from "@tanstack/react-router";
import { UploadCloud } from "lucide-react";

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
  return (
    <div className="flex min-h-[calc(100vh-7rem)] flex-col items-center justify-center">
      <div className="flex max-w-md flex-col items-center text-center">
        <UploadCloud className="h-12 w-12 text-muted-foreground" />
        <h1 className="mt-4 text-xl font-semibold text-foreground">File Upload & Scan</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Upload source code, binaries, or container images to scan.
        </p>
      </div>
    </div>
  );
}
