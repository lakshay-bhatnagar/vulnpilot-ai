import { createFileRoute } from "@tanstack/react-router";
import { FileText } from "lucide-react";

export const Route = createFileRoute("/reports")({
  component: ReportsPage,
  head: () => ({
    meta: [
      { title: "Executive Reports | VulnPilot AI" },
      { name: "description", content: "Executive security reports from VulnPilot AI" },
      { property: "og:title", content: "Executive Reports | VulnPilot AI" },
      { property: "og:description", content: "Executive security reports from VulnPilot AI" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function ReportsPage() {
  return (
    <div className="flex min-h-[calc(100vh-7rem)] flex-col items-center justify-center">
      <div className="flex max-w-md flex-col items-center text-center">
        <FileText className="h-12 w-12 text-muted-foreground" />
        <h1 className="mt-4 text-xl font-semibold text-foreground">Executive Reports</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Generate and download board-ready security summaries.
        </p>
      </div>
    </div>
  );
}
