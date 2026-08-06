import { useCallback, useState } from "react";
import { UploadCloud, FolderOpen, Loader2 } from "lucide-react";
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

const ACCEPTED_EXTENSIONS = [".xml", ".json", ".nessus", ".pcap", ".pcapng"];

function isAcceptedFile(file: File): boolean {
  const lower = file.name.toLowerCase();
  return ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export function DropzoneCard({
  onFilesSelected,
  disabled = false,
}: {
  onFilesSelected?: (files: File[]) => void;
  disabled?: boolean;
}) {
  const [dragging, setDragging] = useState(false);

  const handleFiles = useCallback(
    (fileList: FileList | File[]) => {
      if (disabled) return;

      const files = Array.from(fileList);
      const accepted = files.filter(isAcceptedFile);

      if (accepted.length > 0) {
        onFilesSelected?.(accepted);
      }
    },
    [disabled, onFilesSelected],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      handleFiles(e.dataTransfer.files);
    },
    [handleFiles],
  );

  return (
    <Card className="border-border/60 bg-card">
      <CardContent className="p-6">
        <label
          onDragOver={(e) => {
            e.preventDefault();
            if (!disabled) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={cn(
            "flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-12 text-center transition-colors",
            disabled && "cursor-not-allowed opacity-60",
            dragging
              ? "border-ai-cyan bg-ai-cyan/5"
              : "border-border hover:border-ai-cyan/50 hover:bg-muted/30",
          )}
        >
          <input
            type="file"
            multiple
            accept=".xml,.json,.nessus,.pcap,.pcapng"
            disabled={disabled}
            className="sr-only"
            onChange={(e) => {
              if (e.target.files) handleFiles(e.target.files);
              e.target.value = "";
            }}
          />
          <div className="rounded-full border border-ai-cyan/30 bg-ai-cyan/10 p-4">
            {disabled ? (
              <Loader2 className="h-8 w-8 animate-spin text-ai-cyan" />
            ) : (
              <UploadCloud className="h-8 w-8 text-ai-cyan" />
            )}
          </div>
          <h3 className="mt-4 text-base font-semibold text-foreground">
            {disabled ? "Analyzing scan artifacts…" : "Drop scan artifacts here"}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {disabled
              ? "Uploads are disabled while the AI pipeline is running"
              : "or click to browse — Burp, Nuclei, Nessus, or Wireshark exports"}
          </p>
          <p className="mt-3 flex items-center gap-1.5 font-mono text-xs text-muted-foreground/80">
            <FolderOpen className="h-3.5 w-3.5" />
            .xml · .json · .nessus · .pcap · .pcapng
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
