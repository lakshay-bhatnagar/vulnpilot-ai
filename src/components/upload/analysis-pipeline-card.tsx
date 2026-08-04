import { CheckCircle2, Circle, FileCode2, Loader2, FileJson, Radio } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type StepStatus = "complete" | "active" | "pending";

const STEPS: { title: string; detail: string; status: StepStatus }[] = [
  {
    title: "File Parsing & Schema Standardisation",
    detail: "3 files normalised · 1,284 raw findings ingested",
    status: "complete",
  },
  {
    title: "AI Deduplication & Cross-Tool Clustering",
    detail: "612 / 1,284 findings clustered · 47% duplicates collapsed",
    status: "active",
  },
  {
    title: "CWE / OWASP Top 10 / MITRE ATT&CK Mapping",
    detail: "Awaiting deduplicated finding set",
    status: "pending",
  },
  {
    title: "AI Prioritisation & PoC Generation",
    detail: "Exploitability scoring and PoC synthesis queued",
    status: "pending",
  },
];

const FILES = [
  { name: "burp_scan_api_v1.xml", size: "18.4 MB", tool: "Burp Suite", progress: 100, icon: FileCode2 },
  { name: "nuclei_recon.json", size: "4.2 MB", tool: "Nuclei", progress: 100, icon: FileJson },
  { name: "edge_perimeter.nessus", size: "9.7 MB", tool: "Nessus", progress: 72, icon: FileCode2 },
  { name: "lateral_traffic.pcap", size: "126 MB", tool: "Wireshark", progress: 31, icon: Radio },
];

function StepIcon({ status }: { status: StepStatus }) {
  if (status === "complete")
    return <CheckCircle2 className="h-5 w-5 text-severity-low" />;
  if (status === "active")
    return (
      <span className="relative flex h-5 w-5 items-center justify-center">
        <span className="absolute inline-flex h-5 w-5 animate-ping rounded-full bg-ai-cyan/40" />
        <Loader2 className="relative h-5 w-5 animate-spin text-ai-cyan" />
      </span>
    );
  return <Circle className="h-5 w-5 text-muted-foreground/50" />;
}

export function AnalysisPipelineCard() {
  return (
    <Card className="border-border/60 bg-card">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="text-base">Active Analysis</CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            Session <span className="font-mono">vp-8f42c1</span> · started 2m 14s ago
          </p>
        </div>
        <Badge className="border-ai-cyan/40 bg-ai-cyan/10 text-ai-cyan hover:bg-ai-cyan/10">
          <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-ai-cyan" />
          Running
        </Badge>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-3">
          {FILES.map((f) => (
            <div
              key={f.name}
              className="rounded-lg border border-border/60 bg-muted/20 p-3"
            >
              <div className="flex items-center gap-3">
                <f.icon className="h-4 w-4 shrink-0 text-ai-cyan" />
                <span className="truncate font-mono text-sm text-foreground">
                  {f.name}
                </span>
                <Badge variant="outline" className="ml-auto shrink-0 font-normal">
                  {f.tool}
                </Badge>
                <span className="w-16 shrink-0 text-right font-mono text-xs text-muted-foreground">
                  {f.size}
                </span>
              </div>
              <div className="mt-2 flex items-center gap-3">
                <Progress
                  value={f.progress}
                  className="h-1.5 bg-muted [&>div]:bg-ai-cyan"
                />
                <span className="w-10 shrink-0 text-right font-mono text-xs text-muted-foreground">
                  {f.progress}%
                </span>
              </div>
            </div>
          ))}
        </div>

        <div className="space-y-1">
          {STEPS.map((step, i) => (
            <div key={step.title} className="flex gap-3">
              <div className="flex flex-col items-center">
                <StepIcon status={step.status} />
                {i < STEPS.length - 1 && (
                  <span
                    className={cn(
                      "my-1 w-px flex-1",
                      step.status === "complete" ? "bg-severity-low/40" : "bg-border",
                    )}
                  />
                )}
              </div>
              <div className="pb-5">
                <p
                  className={cn(
                    "text-sm font-medium",
                    step.status === "pending"
                      ? "text-muted-foreground"
                      : "text-foreground",
                  )}
                >
                  Step {i + 1}: {step.title}
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">{step.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
