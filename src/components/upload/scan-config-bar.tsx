import { Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export function ScanConfigBar({
  disabled = false,
  onStartAnalysis,
}: {
  disabled?: boolean;
  onStartAnalysis?: () => void;
}) {
  return (
    <Card className="border-border/60 bg-card">
      <CardContent className="flex justify-end p-4">
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
