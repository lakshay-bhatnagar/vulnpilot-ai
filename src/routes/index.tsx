import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Shield, ScanLine } from "lucide-react";
import { ScanRunDialog } from "@/components/scan/scan-run-dialog";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  component: Index,
  head: () => ({
    meta: [
      { title: "Dashboard | VulnPilot AI" },
      { name: "description", content: "VulnPilot AI dashboard" },
      { property: "og:title", content: "Dashboard | VulnPilot AI" },
      { property: "og:description", content: "VulnPilot AI dashboard" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function Index() {
  const [dialogOpen, setDialogOpen] = useState(false);
  return (
    <div className="flex min-h-[calc(100vh-7rem)] flex-col items-center justify-center">
      <div className="flex max-w-md flex-col items-center text-center">
        <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-border bg-card shadow-sm">
          <Shield className="h-10 w-10 text-ai-cyan" />
        </div>
        <h1 className="mt-6 text-2xl font-semibold tracking-tight text-foreground">
          Welcome to VulnPilot AI
        </h1>
        <p className="mt-3 text-sm text-muted-foreground">
          Select a target system and run a scan to start your AI-powered application security
          assessment.
        </p>
        <Button onClick={() => setDialogOpen(true)} className="mt-6 gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
          <ScanLine className="h-4 w-4" />
          Run Your First Scan
        </Button>
      </div>
      <ScanRunDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  );
}
