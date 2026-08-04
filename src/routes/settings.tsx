import { createFileRoute } from "@tanstack/react-router";
import { Settings } from "lucide-react";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
  head: () => ({
    meta: [
      { title: "Settings | VulnPilot AI" },
      { name: "description", content: "Configure VulnPilot AI" },
      { property: "og:title", content: "Settings | VulnPilot AI" },
      { property: "og:description", content: "Configure VulnPilot AI" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function SettingsPage() {
  return (
    <div className="flex min-h-[calc(100vh-7rem)] flex-col items-center justify-center">
      <div className="flex max-w-md flex-col items-center text-center">
        <Settings className="h-12 w-12 text-muted-foreground" />
        <h1 className="mt-4 text-xl font-semibold text-foreground">Settings</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Manage integrations, notifications, and scan preferences.
        </p>
      </div>
    </div>
  );
}
