# VulnPilot AI

Act as a principal UI/UX engineer specializing in cybersecurity tools like CrowdStrike and SentinelOne.

I am building "VulnPilot AI" – an AI-powered Application Security Copilot.

Design System & Theme Rules:

1. Aesthetic: Modern dark mode cybersecurity platform. Background: slate-950/zinc-950. Cards: slate-900 with subtle border slate-800.

2. Accents: Neon Cyan (#00F0FF) for AI features/actions, Emerald for Low/Passed, Amber for Medium, Orange for High, and Rose/Red (#FF2E63) for Critical vulnerabilities.

3. Component Library: Use Tailwind CSS, Lucide React icons, and Shadcn UI patterns.

4. App Layout: A collapsible left sidebar for navigation, a top header with target system selector + run scan button, and a main content viewport.

Sidebar Navigation Items:

- Dashboard (LayoutGrid icon)

- File Upload & Scan (UploadCloud icon)

- Vulnerabilities (ShieldAlert icon)

- Executive Reports (FileText icon)

- Settings (Settings icon)

Generate the base app Shell layout, dark theme wrapper, sidebar, top bar, and empty main view state.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/277927b6-87c3-49e3-a67a-3bb2f5998f44).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
