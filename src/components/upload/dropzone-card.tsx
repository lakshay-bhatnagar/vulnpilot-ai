import { useCallback, useState } from "react";
import { UploadCloud, FolderOpen } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const SUPPORTED_TOOLS = [
  "Burp Suite XML",
  "Nuclei JSON",
  "Nessus",
  "AppScan",
  "Wireshark PCAP",
];

export function DropzoneCard({ onFiles }: { onFiles?: (names: string[]) => void }) {
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const names = Array.from(e.dataTransfer.files).map((f) => f.name);
      if (names.length) onFiles?.(names);
    },
    [onFiles],
  );

  return (
    <Card className="border-border/60 bg-card">
      <CardContent className="p-6">
        <label
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={cn(
            "flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-12 text-center transition-colors",
            dragging
              ? "border-ai-cyan bg-ai-cyan/5"
              : "border-border hover:border-ai-cyan/50 hover:bg-muted/30",
          )}
        >
          <input
            type="file"
            multiple
            accept=".xml,.json,.nessus,.pcap"
            className="sr-only"
            onChange={(e) =>
              onFiles?.(Array.from(e.target.files ?? []).map((f) => f.name))
            }
          />
          <div className="rounded-full border border-ai-cyan/30 bg-ai-cyan/10 p-4">
            <UploadCloud className="h-8 w-8 text-ai-cyan" />
          </div>
          <h3 className="mt-4 text-base font-semibold text-foreground">
            Drop scan artifacts here
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            or click to browse — multiple files supported
          </p>
          <p className="mt-3 flex items-center gap-1.5 font-mono text-xs text-muted-foreground/80">
            <FolderOpen className="h-3.5 w-3.5" />
            .xml · .json · .nessus · .pcap
          </p>
        </label>

        <div className="mt-5 flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">
            Supported tools:
          </span>
          {SUPPORTED_TOOLS.map((tool) => (
            <Badge
              key={tool}
              variant="outline"
              className="border-border bg-muted/40 font-normal text-muted-foreground"
            >
              {tool}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
