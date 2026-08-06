import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { FolderPlus, Play, Plus, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { ScanRunDialog } from "@/components/scan/scan-run-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { addProjectAsset, createProject, generateProjectExecutiveReport, listProjects, projectReportPreviewUrl, type Project, type ProjectAsset } from "@/lib/scan-api";

export const Route = createFileRoute("/projects")({ component: ProjectsPage });

function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selected, setSelected] = useState<Project | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [assetType, setAssetType] = useState<ProjectAsset["asset_type"]>("domain");
  const [assetValue, setAssetValue] = useState("");
  const [loading, setLoading] = useState(true);
  const [scanOpen, setScanOpen] = useState(false);

  const reload = async () => {
    setLoading(true);
    try {
      const next = await listProjects();
      setProjects(next);
      setSelected((current) => next.find((project) => project.id === current?.id) ?? next[0] ?? null);
    } catch (error) { toast.error("Unable to load projects", { description: error instanceof Error ? error.message : "Start the backend and try again." }); }
    finally { setLoading(false); }
  };
  useEffect(() => { void reload(); }, []);

  const create = async () => {
    try { const project = await createProject(name, description); setName(""); setDescription(""); await reload(); setSelected(project); toast.success("Project created"); }
    catch (error) { toast.error("Could not create project", { description: error instanceof Error ? error.message : "Check the name." }); }
  };
  const addAsset = async () => {
    if (!selected) return;
    try { await addProjectAsset(selected.id, assetType, assetValue); setAssetValue(""); await reload(); toast.success("Asset added to project"); }
    catch (error) { toast.error("Could not add asset", { description: error instanceof Error ? error.message : "Check the asset." }); }
  };
  const regenerateReport = async (sessionId: string) => {
    if (!selected) return;
    try {
      const pdf = await generateProjectExecutiveReport(selected.id, sessionId, { company_name: selected.name, assessment_date: new Date().toISOString().slice(0, 10), assessment_scope: selected.assets.map((asset) => asset.value).join(", ") || selected.name, assessment_type: "Vulnerability Assessment", classification: "Confidential" });
      window.open(URL.createObjectURL(pdf), "_blank", "noopener,noreferrer");
      await reload();
      toast.success("Executive report regenerated from stored scan results");
    } catch (error) { toast.error("Could not regenerate report", { description: error instanceof Error ? error.message : "The session needs stored AI results." }); }
  };

  return <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-6">
    <div className="flex items-center justify-between"><div><h1 className="text-xl font-semibold">Projects</h1><p className="mt-1 text-sm text-muted-foreground">Keep assets, scans, historical findings, and reports together.</p></div><Button variant="outline" onClick={() => void reload()} disabled={loading}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>
    <div className="grid gap-6 lg:grid-cols-[320px_1fr]"><Card><CardHeader><CardTitle className="text-base">Create project</CardTitle></CardHeader><CardContent className="space-y-3"><div><Label>Name</Label><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Customer environment" /></div><div><Label>Description</Label><Input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Optional scope note" /></div><Button className="w-full" onClick={() => void create()} disabled={!name.trim()}><FolderPlus className="mr-2 h-4 w-4" />Create project</Button><div className="border-t pt-4"><p className="mb-2 text-xs font-medium text-muted-foreground">Projects</p>{projects.map((project) => <button key={project.id} onClick={() => setSelected(project)} className={`mb-1 w-full rounded p-2 text-left text-sm ${selected?.id === project.id ? "bg-primary/10 text-primary" : "hover:bg-muted"}`}><span className="block font-medium">{project.name}</span><span className="text-xs text-muted-foreground">Risk {project.risk_score} · {project.scan_history.length} scans</span></button>)}{!loading && !projects.length && <p className="text-xs text-muted-foreground">No projects yet.</p>}</div></CardContent></Card>
      <Card><CardHeader><CardTitle className="text-base">{selected?.name ?? "Select a project"}</CardTitle></CardHeader><CardContent>{selected ? <div className="space-y-5"><div className="grid grid-cols-2 gap-3 sm:grid-cols-4"><Metric label="Risk score" value={selected.risk_score} /><Metric label="Trend" value={selected.trend} /><Metric label="Open" value={selected.open_findings} /><Metric label="Resolved" value={selected.resolved_findings} /></div><div className="flex flex-wrap gap-2">{selected.assets.map((asset) => <span key={asset.id} className="rounded border px-2 py-1 text-xs"><b>{asset.asset_type}</b> · {asset.value}</span>)}{!selected.assets.length && <span className="text-sm text-muted-foreground">No assets added.</span>}</div><div className="grid gap-2 sm:grid-cols-[150px_1fr_auto]"><Select value={assetType} onValueChange={(value: ProjectAsset["asset_type"]) => setAssetType(value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{["domain", "ip", "cidr", "repository", "apk", "ipa"].map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}</SelectContent></Select><Input value={assetValue} onChange={(event) => setAssetValue(event.target.value)} placeholder="Asset value" /><Button variant="outline" onClick={() => void addAsset()} disabled={!assetValue.trim()}><Plus className="mr-1 h-4 w-4" />Add asset</Button></div><div className="flex items-center justify-between border-t pt-4"><div><p className="text-sm font-medium">Scan sessions</p><p className="text-xs text-muted-foreground">Rescans automatically compare new, resolved, and recurring findings.</p></div><Button onClick={() => setScanOpen(true)}><Play className="mr-2 h-4 w-4" />Run scan</Button></div><div className="space-y-2">{selected.scan_history.map((session) => <div key={session.id} className="rounded border p-3 text-sm"><b>{session.target}</b><span className="ml-2 text-muted-foreground">{session.scan_type} · risk {session.risk_score}</span><div className="mt-2 flex gap-2"><Button size="sm" variant="outline" onClick={() => void regenerateReport(session.id)}>Regenerate report</Button>{session.report_path && <Button size="sm" variant="outline" asChild><a href={projectReportPreviewUrl(selected.id, session.id)} target="_blank" rel="noreferrer">Preview report</a></Button>}</div><p className="mt-2 text-xs text-muted-foreground">{session.completed_at ? `Completed ${new Date(session.completed_at).toLocaleString()}` : session.status}{session.report_path ? " · Executive report available" : ""}</p></div>)}</div></div> : <p className="text-sm text-muted-foreground">Create a project to begin grouping assets and scan sessions.</p>}</CardContent></Card></div>
    {selected && <ScanRunDialog open={scanOpen} onOpenChange={setScanOpen} projectId={selected.id} />}
  </div>;
}

function Metric({ label, value }: { label: string; value: string | number }) { return <div className="rounded border p-3"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-1 text-lg font-semibold capitalize">{value}</p></div>; }
