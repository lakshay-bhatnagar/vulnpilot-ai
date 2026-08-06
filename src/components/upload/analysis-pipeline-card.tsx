import { CheckCircle2, Circle, FileCode2, Loader2, FileJson } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useScan, type PipelineStepStatus } from "@/lib/scan-context";

function StepIcon({ status }: { status: PipelineStepStatus }) {
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

function fileIcon(name: string) {
  return name.toLowerCase().endsWith(".json") ? FileJson : FileCode2;
}

function formatDuration(durationMs?: number): string {
  if (durationMs === undefined) return "Not available";
  return durationMs < 1000 ? `${durationMs} ms` : `${(durationMs / 1000).toFixed(1)} s`;
}

export function AnalysisPipelineCard() {
  const { uploadFiles, pipelineSteps, isLoading, sessionLabel } = useScan();
  const hasActivity = uploadFiles.length > 0;

  return (
    <Card className="border-border/60 bg-card">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="text-base">Active Analysis</CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            {sessionLabel ? (
              <>
                Session <span className="font-mono">{sessionLabel}</span>
              </>
            ) : (
              "Upload a scan file to start the pipeline"
            )}
          </p>
        </div>
        <Badge
          className={cn(
            "border-ai-cyan/40 bg-ai-cyan/10 text-ai-cyan hover:bg-ai-cyan/10",
            !isLoading && !hasActivity && "border-border/60 bg-muted/40 text-muted-foreground",
          )}
        >
          {isLoading ? (
            <>
              <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-ai-cyan" />
              Running
            </>
          ) : hasActivity ? (
            "Complete"
          ) : (
            "Idle"
          )}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-6">
        {hasActivity ? (
          <div className="space-y-3">
            {uploadFiles.map((f) => {
              const Icon = fileIcon(f.name);
              return (
                <div
                  key={f.id}
                  className="rounded-lg border border-border/60 bg-muted/20 p-3"
                >
                  <div className="flex items-center gap-3">
                    <Icon className="h-4 w-4 shrink-0 text-ai-cyan" />
                    <span className="truncate font-mono text-sm text-foreground">
                      {f.name}
                    </span>
                    <Badge variant="outline" className="ml-auto shrink-0 font-normal">
                      {f.tool}
                    </Badge>
                    <span className="w-16 shrink-0 text-right font-mono text-xs text-muted-foreground">
                      {f.sizeLabel}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-3">
                    <Progress
                      value={f.progress}
                      className={cn(
                        "h-1.5 bg-muted [&>div]:bg-ai-cyan",
                        f.status === "error" && "[&>div]:bg-severity-critical",
                      )}
                    />
                    <span className="w-10 shrink-0 text-right font-mono text-xs text-muted-foreground">
                      {f.status === "error" ? "Err" : `${f.progress}%`}
                    </span>
                  </div>
                  {(f.status === "complete" || f.status === "error") && (
                    <div className="mt-3 grid gap-2 border-t border-border/50 pt-3 text-xs sm:grid-cols-2">
                      <div><p className="text-muted-foreground">Detected Scanner</p><p className="mt-0.5 font-medium text-foreground">{f.detectedScanner ?? f.tool}</p></div>
                      <div><p className="text-muted-foreground">Number of findings</p><p className="mt-0.5 font-medium text-foreground">{f.findingCount ?? "—"}</p></div>
                      <div><p className="text-muted-foreground">Analysis status</p><p className="mt-0.5 font-medium text-foreground">{f.analysisStatus ?? (f.status === "complete" ? "Complete" : "Failed")}</p></div>
                      <div><p className="text-muted-foreground">Processing duration</p><p className="mt-0.5 font-medium text-foreground">{formatDuration(f.processingDurationMs)}</p></div>
                      {f.status === "complete" && <div className="sm:col-span-2"><p className="text-muted-foreground">AI Engine</p><p className="mt-0.5 font-medium text-foreground">{f.aiEngine ?? "OpenRouter"}</p></div>}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="rounded-lg border border-dashed border-border/60 bg-muted/20 p-6 text-center text-sm text-muted-foreground">
            Pipeline progress will appear here after you upload Burp or Nuclei scan exports.
          </p>
        )}

        <div className="space-y-1">
          {pipelineSteps.map((step, i) => (
            <div key={step.title} className="flex gap-3">
              <div className="flex flex-col items-center">
                <StepIcon status={step.status} />
                {i < pipelineSteps.length - 1 && (
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
