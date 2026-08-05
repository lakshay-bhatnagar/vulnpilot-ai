import { Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function ScanConfigBar({
  disabled = false,
  onStartAnalysis,
}: {
  disabled?: boolean;
  onStartAnalysis?: () => void;
}) {
  return (
    <Card className="border-border/60 bg-card">
      <CardContent className="flex flex-col gap-4 p-4 lg:flex-row lg:items-end">
        <div className="flex-1 space-y-1.5">
          <Label className="text-xs text-muted-foreground">Target Environment</Label>
          <Select defaultValue="production" disabled={disabled}>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="production">Production</SelectItem>
              <SelectItem value="staging">Staging</SelectItem>
              <SelectItem value="internal-dev">Internal Dev</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex-1 space-y-1.5">
          <Label className="text-xs text-muted-foreground">LLM Model</Label>
          <Select defaultValue="claude-3-7-sonnet" disabled={disabled}>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="claude-3-7-sonnet">Claude 3.7 Sonnet</SelectItem>
              <SelectItem value="deepseek-r1-local">DeepSeek-R1 Local</SelectItem>
              <SelectItem value="gpt-4o">GPT-4o</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Button
          type="button"
          disabled={disabled}
          onClick={onStartAnalysis}
          className="border border-ai-cyan/60 bg-ai-cyan/10 text-ai-cyan shadow-[0_0_20px_-4px_var(--ai-cyan)] transition-shadow hover:bg-ai-cyan/20 hover:shadow-[0_0_28px_-2px_var(--ai-cyan)] lg:w-auto"
          size="lg"
        >
          <Sparkles className="mr-2 h-4 w-4" />
          View Vulnerability Dashboard
        </Button>
      </CardContent>
    </Card>
  );
}
