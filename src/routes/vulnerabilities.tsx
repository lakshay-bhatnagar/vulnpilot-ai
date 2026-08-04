import { createFileRoute } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";

export const Route = createFileRoute("/vulnerabilities")({
  component: VulnerabilitiesPage,
  head: () => ({
    meta: [
      { title: "Vulnerabilities | VulnPilot AI" },
      { name: "description", content: "Review vulnerabilities with VulnPilot AI" },
      { property: "og:title", content: "Vulnerabilities | VulnPilot AI" },
      { property: "og:description", content: "Review vulnerabilities with VulnPilot AI" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function VulnerabilitiesPage() {
  return (
    <div className="flex min-h-[calc(100vh-7rem)] flex-col items-center justify-center">
      <div className="flex max-w-md flex-col items-center text-center">
        <ShieldAlert className="h-12 w-12 text-muted-foreground" />
        <h1 className="mt-4 text-xl font-semibold text-foreground">Vulnerabilities</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Triaged findings and AI remediation guidance will appear here.
        </p>
      </div>
    </div>
  );
}
