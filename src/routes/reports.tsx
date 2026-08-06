import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Download, Eye, FileText, Loader2, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { generateExecutiveReport, type ReportMetadata } from "@/lib/scan-api";
import { useScan } from "@/lib/scan-context";

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
  const { hasScanData } = useScan();
  const [metadata, setMetadata] = useState<ReportMetadata>({
    company_name: "VulnPilot AI Client",
    assessment_date: new Date().toISOString().slice(0, 10),
    assessment_scope: "Latest uploaded scan artifacts",
    assessment_type: "Vulnerability Assessment",
    classification: "Confidential",
  });
  const [isGenerating, setIsGenerating] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  const update = (field: keyof ReportMetadata, value: string) => {
    setMetadata((current) => ({ ...current, [field]: value }));
  };

  const generate = async () => {
    if (!hasScanData) {
      toast.error("No scan data available", { description: "Upload a scan before generating a report." });
      return;
    }
    setIsGenerating(true);
    try {
      const pdf = await generateExecutiveReport(metadata);
      const url = URL.createObjectURL(pdf);
      setPreviewUrl((current) => {
        if (current) URL.revokeObjectURL(current);
        return url;
      });
      toast.success("Executive report generated", { description: "The preview reflects the latest scan results." });
    } catch (error) {
      toast.error("Report generation failed", {
        description: error instanceof Error ? error.message : "Please try again.",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const download = () => {
    if (!previewUrl) return;
    const link = document.createElement("a");
    link.href = previewUrl;
    link.download = "vulnpilot-executive-report.pdf";
    link.click();
  };

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Executive Reports</h1>
        <p className="mt-1 text-sm text-muted-foreground">Generate a board-ready security assessment from the latest scan.</p>
      </div>
      <div className="grid gap-6 lg:grid-cols-[360px_1fr]">
        <Card className="h-fit border-border/60">
          <CardHeader><CardTitle className="flex items-center gap-2 text-base"><FileText className="h-4 w-4 text-ai-cyan" /> Report details</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5"><Label htmlFor="company">Company name</Label><Input id="company" value={metadata.company_name} onChange={(event) => update("company_name", event.target.value)} /></div>
            <div className="space-y-1.5"><Label htmlFor="date">Assessment date</Label><Input id="date" type="date" value={metadata.assessment_date} onChange={(event) => update("assessment_date", event.target.value)} /></div>
            <div className="space-y-1.5"><Label htmlFor="scope">Assessment scope</Label><Input id="scope" value={metadata.assessment_scope} onChange={(event) => update("assessment_scope", event.target.value)} /></div>
            <div className="space-y-1.5"><Label htmlFor="type">Assessment type</Label><Input id="type" value={metadata.assessment_type} onChange={(event) => update("assessment_type", event.target.value)} /></div>
            <div className="space-y-1.5"><Label htmlFor="classification">Classification</Label><Input id="classification" value={metadata.classification} onChange={(event) => update("classification", event.target.value)} /></div>
            <Button className="w-full gap-2" onClick={generate} disabled={isGenerating || !hasScanData}>
              {isGenerating ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              {previewUrl ? "Regenerate report" : "Generate report"}
            </Button>
            {!hasScanData && <p className="text-xs text-muted-foreground">Upload and analyze a scan to enable report generation.</p>}
          </CardContent>
        </Card>
        <Card className="min-h-[680px] border-border/60">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 border-b border-border/60">
            <CardTitle className="text-base">PDF Preview</CardTitle>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" className="gap-1.5" onClick={generate} disabled={isGenerating || !hasScanData}><Eye className="h-3.5 w-3.5" /> Preview</Button>
              <Button size="sm" className="gap-1.5" onClick={download} disabled={!previewUrl}><Download className="h-3.5 w-3.5" /> Download</Button>
            </div>
          </CardHeader>
          <CardContent className="h-[620px] p-3">
            {previewUrl ? <iframe title="Executive security report preview" src={previewUrl} className="h-full w-full rounded border border-border/60 bg-white" /> : <div className="flex h-full flex-col items-center justify-center text-center"><FileText className="h-12 w-12 text-muted-foreground" /><p className="mt-3 text-sm font-medium">No report generated</p><p className="mt-1 text-xs text-muted-foreground">Complete the details and generate a preview.</p></div>}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
