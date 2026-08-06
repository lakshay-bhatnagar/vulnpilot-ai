import { useState } from "react";
import { Play, Shield } from "lucide-react";
import { ScanRunDialog } from "@/components/scan/scan-run-dialog";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const targets = [
  { value: "production-api", label: "Production API" },
  { value: "staging-web", label: "Staging Web App" },
  { value: "mobile-app", label: "Mobile Backend" },
  { value: "internal-portal", label: "Internal Portal" },
];

export function TopHeader() {
  const [dialogOpen, setDialogOpen] = useState(false);
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-border bg-card/80 px-4 backdrop-blur-md">
      <div className="flex items-center gap-3">
        <SidebarTrigger className="text-foreground hover:bg-accent hover:text-foreground" />
        <div className="hidden items-center gap-2 md:flex">
          <Shield className="h-5 w-5 text-ai-cyan" />
          <span className="text-sm font-semibold text-foreground">VulnPilot AI</span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="hidden text-xs font-medium text-muted-foreground sm:inline">
            Target system
          </span>
          <Select defaultValue="production-api">
            <SelectTrigger className="h-9 w-[200px] border-border bg-background text-foreground focus:ring-ai-cyan">
              <SelectValue placeholder="Select target" />
            </SelectTrigger>
            <SelectContent className="border-border bg-card text-card-foreground">
              {targets.map((target) => (
                <SelectItem
                  key={target.value}
                  value={target.value}
                  className="focus:bg-accent focus:text-accent-foreground"
                >
                  {target.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Button onClick={() => setDialogOpen(true)} className="gap-2 bg-primary text-primary-foreground shadow-primary/35 shadow-lg hover:bg-primary/90">
          <Play className="h-4 w-4 fill-current" />
          Run Scan
        </Button>
      </div>
      <ScanRunDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </header>
  );
}
