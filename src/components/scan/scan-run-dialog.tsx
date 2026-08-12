import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Loader2, Play, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { createDependencyScanJob, createMobileScanJob, createScanJob, createSourceCodeScanJob, getScanAnalysis, getScanJobEventsUrl, type ProfileMode, type ScanJob, type ScanProfile, type ScannerName } from "@/lib/scan-api";
import { useScan } from "@/lib/scan-context";

const SCAN_TYPES: Record<ScannerName, string[]> = {
  nmap: ["default", "discovery", "tcp", "udp", "version", "os", "nse", "service", "ssl", "http"],
  nuclei: ["default", "web", "technology", "cve"],
  mobsf: ["default", "android", "ios", "static"],
};

const PROFILES: { value: ScanProfile; label: string; description: string }[] = [
  { value: "external_attack_surface", label: "External Attack Surface", description: "Subdomain, DNS, HTTP, port, crawl, parameter, and template-driven coverage." },
  { value: "web_application_assessment", label: "Web Application Assessment", description: "HTTP discovery, crawling, parameter discovery, and Nuclei checks." },
  { value: "infrastructure_assessment", label: "Infrastructure Assessment", description: "Port discovery, service fingerprinting/NSE, and Nuclei checks." },
  { value: "mobile_assessment", label: "Mobile Assessment", description: "APK: APKTool, JADX, MobSF, Semgrep, Trivy, SBOM, and OSV dependency analysis. IPA: MobSF plus extracted static analysis." },
  { value: "source_code_assessment", label: "Source Code Assessment", description: "Available source-target checks through the installed scanner set." },
  { value: "software_composition_analysis", label: "Software Composition Analysis", description: "Generate an SBOM and identify vulnerable project dependencies with Syft, Trivy, and OSV Scanner." },
  { value: "custom_scan", label: "Custom Scan", description: "Choose one scanner and its scan type manually." },
];

function elapsed(job: ScanJob, now: number): string {
  const start = job.started_time ?? job.created_time;
  const end = job.completed_time ?? new Date(now).toISOString();
  const seconds = Math.max(0, Math.floor((Date.parse(end) - Date.parse(start)) / 1000));
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export function ScanRunDialog({ open, onOpenChange, projectId }: { open: boolean; onOpenChange: (open: boolean) => void; projectId?: string }) {
  const navigate = useNavigate();
  const { setScanAnalysis } = useScan();
  const [target, setTarget] = useState("");
  const [scanner, setScanner] = useState<ScannerName>("nmap");
  const [scanProfile, setScanProfile] = useState<ScanProfile>("custom_scan");
  const [profileMode, setProfileMode] = useState<ProfileMode>("standard");
  const [sourceArchive, setSourceArchive] = useState<File | null>(null);
  const [mobilePackage, setMobilePackage] = useState<File | null>(null);
  const [scanType, setScanType] = useState("default");
  const [depth, setDepth] = useState<"shallow" | "standard" | "deep">("standard");
  const [advancedOptions, setAdvancedOptions] = useState("");
  const [nucleiTags, setNucleiTags] = useState("");
  const [generateExecutiveReport, setGenerateExecutiveReport] = useState(false);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [streamConnected, setStreamConnected] = useState(false);
  const [now, setNow] = useState(Date.now());
  const completedJobIds = useRef(new Set<string>());

  const isTerminal = job?.status === "Completed" || job?.status === "Failed" || job?.status === "Cancelled";
  const customArgs = useMemo(() => {
    const args = advancedOptions.trim() ? advancedOptions.trim().split(/\s+/) : [];
    if (scanner === "nuclei" && nucleiTags.trim()) args.push("-tags", nucleiTags.trim());
    return args;
  }, [advancedOptions, nucleiTags, scanner]);

  useEffect(() => {
    if (!job || isTerminal) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [isTerminal, job]);

  useEffect(() => {
    if (!job || isTerminal) return;

    let eventSource: EventSource | null = null;
    let reconnectTimer: number | undefined;
    let disposed = false;
    let reconnectAttempts = 0;

    const handleCompletedJob = async (next: ScanJob) => {
      if (completedJobIds.current.has(next.job_id)) return;
      completedJobIds.current.add(next.job_id);
      try {
        const analysis = next.analysis ?? await getScanAnalysis(next.job_id);
        setScanAnalysis(analysis);
        toast.success("Scan complete", { description: `${next.finding_count} findings are ready on the dashboard.` });
        onOpenChange(false);
        navigate({ to: "/vulnerabilities" });
      } catch (error) {
        completedJobIds.current.delete(next.job_id);
        toast.error("Unable to load scan results", { description: error instanceof Error ? error.message : "Please try again." });
      }
    };

    const connect = () => {
      if (disposed) return;
      eventSource = new EventSource(getScanJobEventsUrl(job.job_id));
      eventSource.onopen = () => {
        reconnectAttempts = 0;
        setStreamConnected(true);
      };
      eventSource.addEventListener("scan-update", (event) => {
        try {
          const next = JSON.parse((event as MessageEvent<string>).data) as ScanJob;
          setJob(next);
          if (next.status === "Completed") void handleCompletedJob(next);
          if (next.status === "Failed") toast.error("Scan failed", { description: next.error_message ?? "The scanner could not complete." });
        } catch (error) {
          console.error("[VulnPilot scan] invalid SSE job update", error);
        }
      });
      eventSource.onerror = () => {
        eventSource?.close();
        setStreamConnected(false);
        if (disposed) return;
        const delay = Math.min(1000 * 2 ** reconnectAttempts, 10000);
        reconnectAttempts += 1;
        reconnectTimer = window.setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      disposed = true;
      eventSource?.close();
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      setStreamConnected(false);
    };
  }, [isTerminal, job?.job_id, navigate, onOpenChange, setScanAnalysis]);

  const submit = async () => {
    const isProjectProfile = scanProfile === "source_code_assessment" || scanProfile === "software_composition_analysis";
    const isMobileProfile = scanProfile === "mobile_assessment";
    if (!target.trim() && !(isProjectProfile && sourceArchive) && !(isMobileProfile && mobilePackage)) {
      toast.error("Target required", { description: "Enter a host, URL, IP address, CIDR, or MobSF package path." });
      return;
    }
    setIsSubmitting(true);
    try {
      const nextJob = scanProfile === "source_code_assessment"
        ? await createSourceCodeScanJob({ sourceLocation: target.trim(), archive: sourceArchive, profileMode, generateExecutiveReport, projectId })
        : scanProfile === "software_composition_analysis"
          ? await createDependencyScanJob({ sourceLocation: target.trim(), archive: sourceArchive, profileMode, generateExecutiveReport, projectId })
          : scanProfile === "mobile_assessment" && mobilePackage
            ? await createMobileScanJob({ file: mobilePackage, profileMode, generateExecutiveReport, projectId })
        : await createScanJob({
          scanner,
          target: target.trim(),
          scan_type: scanType,
          depth,
          scan_profile: scanProfile,
          profile_mode: profileMode,
          custom_args: customArgs,
          generate_executive_report: generateExecutiveReport,
          project_id: projectId,
        });
      setJob(nextJob);
    } catch (error) {
      toast.error("Unable to create scan job", { description: error instanceof Error ? error.message : "Please review the configuration." });
    } finally {
      setIsSubmitting(false);
    }
  };

  const reset = () => {
    setJob(null);
    setStreamConnected(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Scan Configuration</DialogTitle>
          <DialogDescription>Start a scanner job. Results are normalized and analyzed when all configured scanner work completes.</DialogDescription>
        </DialogHeader>
        {job ? (
          <div className="space-y-4 rounded-lg border border-border/60 bg-card/50 p-4">
            <div className="flex items-center justify-between gap-3"><div><p className="text-sm font-semibold">{job.status}</p><p className="text-xs text-muted-foreground">{job.current_phase}</p></div><span className="font-mono text-xs text-muted-foreground">{elapsed(job, now)}</span></div>
            <Progress value={job.progress} />
            <div className="grid grid-cols-2 gap-3 text-sm"><div><p className="text-xs text-muted-foreground">Current scanner</p><p>{job.current_scanner ?? job.scanner}</p></div><div><p className="text-xs text-muted-foreground">Finding count</p><p>{job.finding_count}</p></div><div><p className="text-xs text-muted-foreground">Target</p><p className="truncate">{job.target}</p></div><div><p className="text-xs text-muted-foreground">Progress</p><p>{job.progress}%</p></div></div>
            {job.detected_languages.length > 0 && <p className="text-xs text-muted-foreground">Detected languages: {job.detected_languages.join(", ")}</p>}
            {job.mobile_type && <p className="text-xs text-muted-foreground">Detected mobile package: {job.mobile_type.toUpperCase()}</p>}
            {job.tool_results.length > 0 && <div className="border-t border-border/60 pt-3"><p className="mb-2 text-xs font-medium text-muted-foreground">Tool results</p><div className="flex flex-wrap gap-2">{job.tool_results.map((tool) => <span key={tool.scanner} className="rounded border border-border/60 px-2 py-1 text-xs"><span className="font-medium">{tool.scanner}</span> · {tool.status}{tool.finding_count > 0 ? ` (${tool.finding_count})` : ""}</span>)}</div></div>}
            {!isTerminal && <p className="text-xs text-muted-foreground">{streamConnected ? "Live progress connected" : "Reconnecting to live progress…"}</p>}
            {job.error_message && <p className="rounded bg-destructive/10 p-3 text-sm text-destructive">{job.error_message}</p>}
            {job.status === "Failed" || job.status === "Cancelled" ? <Button variant="outline" className="gap-2" onClick={reset}><RotateCcw className="h-4 w-4" /> Configure another scan</Button> : <p className="text-xs text-muted-foreground">The dashboard opens automatically after AI analysis completes.</p>}
          </div>
        ) : (
          <div className="grid gap-4 py-1 sm:grid-cols-2">
            {scanProfile !== "mobile_assessment" && <div className="space-y-1.5 sm:col-span-2"><Label htmlFor="scan-target">{scanProfile === "source_code_assessment" || scanProfile === "software_composition_analysis" ? "Git repository URL or backend-local folder" : "Target"}</Label><Input id="scan-target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder={scanProfile === "source_code_assessment" || scanProfile === "software_composition_analysis" ? "https://github.com/org/repository.git or /srv/projects/app" : "https://app.example.com or 10.0.0.0/24"} /></div>}
            <div className="space-y-1.5"><Label>Scan profile</Label><Select value={scanProfile} onValueChange={(value: ScanProfile) => setScanProfile(value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{PROFILES.map((profile) => <SelectItem key={profile.value} value={profile.value}>{profile.label}</SelectItem>)}</SelectContent></Select></div>
            <div className="space-y-1.5"><Label>Mode</Label><Select value={profileMode} onValueChange={(value: ProfileMode) => setProfileMode(value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="quick">Quick</SelectItem><SelectItem value="standard">Standard</SelectItem><SelectItem value="comprehensive">Comprehensive</SelectItem></SelectContent></Select></div>
            {scanProfile === "mobile_assessment" ? <><p className="rounded-md border border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground sm:col-span-2">{PROFILES.find((profile) => profile.value === scanProfile)?.description} Package type is detected automatically.</p><div className="space-y-1.5 sm:col-span-2"><Label htmlFor="mobile-package">APK or IPA package</Label><Input id="mobile-package" type="file" accept=".apk,.ipa,application/vnd.android.package-archive" onChange={(event) => setMobilePackage(event.target.files?.[0] ?? null)} /></div></> : scanProfile === "source_code_assessment" || scanProfile === "software_composition_analysis" ? <><p className="rounded-md border border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground sm:col-span-2">{PROFILES.find((profile) => profile.value === scanProfile)?.description} Upload a ZIP/TAR archive, or provide exactly one Git URL or backend-local project folder.</p><div className="space-y-1.5 sm:col-span-2"><Label htmlFor="source-archive">Project archive (optional when using URL or local folder)</Label><Input id="source-archive" type="file" accept=".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz" onChange={(event) => setSourceArchive(event.target.files?.[0] ?? null)} /></div></> : scanProfile !== "custom_scan" ? <p className="rounded-md border border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground">{PROFILES.find((profile) => profile.value === scanProfile)?.description}</p> : <><div className="space-y-1.5"><Label>Scanner</Label><Select value={scanner} onValueChange={(value: ScannerName) => { setScanner(value); setScanType("default"); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="nmap">Nmap</SelectItem><SelectItem value="nuclei">Nuclei</SelectItem><SelectItem value="mobsf">MobSF</SelectItem></SelectContent></Select></div><div className="space-y-1.5"><Label>Scan type</Label><Select value={scanType} onValueChange={setScanType}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{SCAN_TYPES[scanner].map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}</SelectContent></Select></div><div className="space-y-1.5"><Label>Depth</Label><Select value={depth} onValueChange={(value: "shallow" | "standard" | "deep") => setDepth(value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="shallow">Shallow</SelectItem><SelectItem value="standard">Standard</SelectItem><SelectItem value="deep">Deep</SelectItem></SelectContent></Select></div><div className="space-y-1.5"><Label htmlFor="nuclei-tags">Custom Nuclei tags</Label><Input id="nuclei-tags" disabled={scanner !== "nuclei"} value={nucleiTags} onChange={(event) => setNucleiTags(event.target.value)} placeholder="cve,exposure" /></div><div className="space-y-1.5 sm:col-span-2"><Label htmlFor="advanced-options">Advanced options / custom Nmap arguments</Label><Textarea id="advanced-options" value={advancedOptions} onChange={(event) => setAdvancedOptions(event.target.value)} placeholder="Example: -p 80,443 -T4 (arguments are passed safely without a shell)" /></div></>}
            <label htmlFor="generate-executive-report" className="flex cursor-pointer items-start gap-3 rounded-md border border-border/60 p-3 text-sm sm:col-span-2">
              <Checkbox id="generate-executive-report" checked={generateExecutiveReport} onCheckedChange={(checked) => setGenerateExecutiveReport(checked === true)} />
              <span><span className="font-medium">Generate Executive Report</span><span className="mt-0.5 block text-xs text-muted-foreground">Create and store report.pdf in this scan’s results folder after AI analysis completes.</span></span>
            </label>
          </div>
        )}
        {!job && <DialogFooter><Button onClick={submit} disabled={isSubmitting} className="gap-2">{isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 fill-current" />} Start scan</Button></DialogFooter>}
      </DialogContent>
    </Dialog>
  );
}
