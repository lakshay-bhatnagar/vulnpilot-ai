# 🛡️ VulnPilot
AI-Powered Security Assessment & Vulnerability Analysis Platform

VulnPilot is an AI-powered security assessment platform designed to unify application security, mobile security, reconnaissance, vulnerability discovery, and AI-assisted analysis into a single workflow.

It integrates industry-standard security tools into configurable pipelines, normalizes findings from different scanners, reduces duplicate scanning, preserves evidence, and uses AI to help security professionals understand, prioritize, correlate, and remediate vulnerabilities.

> ⚠️ **Security Notice:** VulnPilot is intended for authorized security testing, vulnerability assessment, research, and defensive security operations. Only scan systems, applications, networks, and assets that you own or have explicit permission to test.

---

## ✨ Key Capabilities

### 🔍 Security Assessment

VulnPilot brings multiple security testing capabilities together:

* 🌐 Web Application Security Testing
* 🔌 API Security Testing
* 📱 Android APK Security Analysis
* 🍎 iOS Security Analysis
* 💻 Infrastructure & Network Security Assessment
* 🔐 SAST
* 📦 Software Composition Analysis (SCA)
* 🕷️ DAST
* 🌎 External Attack Surface Discovery
* 🤖 AI-Assisted Vulnerability Analysis

---

## 🧩 Application Security

VulnPilot integrates multiple security analysis engines into a unified workflow.

### SAST

Source-code security analysis powered by:

* **Semgrep:** Used to identify security issues directly within application source code.

### SCA

Dependency and open-source component analysis using:

* **OSV**
* **Trivy**

The SCA pipeline helps identify known vulnerabilities in application dependencies and packages.

### DAST

Dynamic application security testing using:

* **Nuclei**
* Reconnaissance-driven target discovery

Discovered endpoints and assets can be fed into subsequent security testing stages.

---

## 📱 Android Security Analysis

VulnPilot supports automated Android application assessment from uploaded APK files.

The Android pipeline is designed to combine static analysis, reverse engineering, and security scanning.

### Android Analysis Stack

```text
APK
 │
 ├── APKTool
 │
 ├── JADX
 │
 ├── MobSF
 │
 ├── Semgrep
 │
 ├── Trivy / Dependency Analysis
 │
 └── AI Security Analysis
        │
        ▼
   Normalized Findings
        │
        ▼
   Risk Prioritization
        │
        ▼
      Report

```

The Android analysis workflow can be extended with dynamic testing and runtime instrumentation using tools such as:

* ADB
* Frida
* Objection
* MobSF
* JADX
* APKTool
* Ghidra

---

## 🌐 Reconnaissance Engine

One of VulnPilot's core components is the configurable **ReconPipeline**.

Instead of running individual reconnaissance tools independently, VulnPilot orchestrates multiple tools and passes useful intermediate results between stages.

### Scan Profiles

#### ⚡ Quick Recon

Designed for rapid attack-surface discovery.

```text
Subfinder
   ↓
HTTPX
   ↓
DNSX
   ↓
Nuclei

```

#### 🔎 Standard Recon

Provides deeper discovery while maintaining reasonable execution time.

```text
Subfinder
   ↓
Amass Passive
   ↓
DNSX
   ↓
HTTPX
   ↓
Naabu
   ↓
Nmap
   ↓
Katana
   ↓
Arjun
   ↓
Nuclei

```

#### 🧠 Deep Recon

Designed for comprehensive external reconnaissance.

```text
Subfinder
   ↓
Amass Active
   ↓
DNSX
   ↓
HTTPX
   ↓
Naabu
   ↓
Masscan (Optional)
   ↓
Nmap
   ↓
Katana
   ↓
Feroxbuster
   ↓
WaybackURLs
   ↓
GAU
   ↓
Arjun
   ↓
Nuclei

```

---

## ⚙️ ReconPipeline

The **ReconPipeline** is designed as a configurable orchestration layer rather than a collection of independent scanner wrappers.

### Pipeline Features

* Create custom scan profiles
* Enable or disable individual tools
* Configure custom tool flags
* Persist intermediate results
* Reuse results between pipeline stages
* Avoid unnecessary rescanning
* Detect previously scanned assets
* Feed discovered assets into subsequent tools
* Maintain scanner-specific evidence
* Support different reconnaissance depths

For example:

```text
Subfinder
   │
   ├── discovered subdomains
   │
   ▼
DNSX
   │
   ├── resolved domains
   │
   ▼
HTTPX
   │
   ├── live web services
   │
   ├── technologies
   │
   └── HTTP metadata
   │
   ▼
Naabu / Nmap
   │
   ├── open ports
   └── services
   │
   ▼
Katana
   │
   └── discovered URLs
   │
   ▼
Arjun
   │
   └── parameters
   │
   ▼
Nuclei
   │
   └── security findings

```

This allows VulnPilot to build a progressively richer representation of the target rather than treating each scanner's output as an isolated result.

---

## 🤖 AI Security Analysis

VulnPilot adds an AI analysis layer on top of traditional security tooling.

Instead of simply displaying raw scanner output, the platform is designed to transform findings into security-relevant context.

### AI Capabilities

* Finding analysis
* Vulnerability explanation
* Severity assessment
* Risk prioritization
* Finding correlation
* Duplicate finding reduction
* Impact analysis
* Remediation recommendations
* Evidence-aware analysis
* Security report generation

The objective is to allow security engineers to move from:

```text
Raw Scanner Output
       ↓
Finding Normalization
       ↓
Deduplication
       ↓
Correlation
       ↓
AI Analysis
       ↓
Risk Prioritization
       ↓
Remediation
       ↓
Security Report

```

---

## 🏗️ High-Level Architecture

```text
                         ┌─────────────────────┐
                         │      VulnPilot      │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
        Application           Reconnaissance           Mobile
         Security                 Engine              Security
              │                     │                     │
      ┌───────┼───────┐       ┌─────┼─────┐         ┌────┼────┐
      │       │       │       │     │     │         │    │    │
     SAST    SCA     DAST    DNS   HTTP   Network   APK  Static Dynamic
      │       │       │       │     │     │         │
   Semgrep  OSV    Nuclei  DNSX  HTTPX Nmap       MobSF
            Trivy                 Nuclei           JADX
                                                  APKTool
                                                     │
              └─────────────────────┬───────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Finding Normalizer  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Deduplication &     │
                         │ Correlation Engine  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     AI Analysis     │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
                Prioritize      Remediation      Reports

```

---

## 🛠️ Technology Stack

### Backend

* Python
* FastAPI
* REST APIs
* SQLite / PostgreSQL
* Redis

### Frontend

* React
* Modern dashboard-based UI

### AI

* OpenAI-compatible LLM APIs
* Anthropic-compatible models
* OpenRouter
* LangGraph

### Security Tooling

| Category | Tools |
| --- | --- |
| **SAST** | Semgrep |
| **SCA** | OSV, Trivy |
| **DAST** | Nuclei |
| **Subdomain Discovery** | Subfinder, Amass |
| **DNS** | DNSX |
| **HTTP Probing** | HTTPX |
| **Port Scanning** | Naabu, Nmap, Masscan |
| **Crawling** | Katana |
| **Content Discovery** | Feroxbuster |
| **Parameter Discovery** | Arjun |
| **Historical Discovery** | GAU, WaybackURLs |
| **Android** | MobSF, JADX, APKTool |
| **Runtime Analysis** | Frida, Objection |
| **Reverse Engineering** | Ghidra |
| **Network Analysis** | Nmap, Wireshark |

---

## 📊 Finding Processing

VulnPilot is designed to handle security findings from different scanners through a common processing layer.

A typical finding can contain:

```text
Finding
├── Title
├── Severity
├── CVSS
├── CWE
├── OWASP Category
├── Affected Asset
├── Evidence
├── Scanner
├── Location
├── Description
├── Impact
├── Remediation
└── References

```

This allows findings from different tools to be compared, correlated, deduplicated, and presented consistently.

---

## 🚀 Example Workflow

A typical external assessment can follow:

```text
Target
  │
  ▼
Recon Profile Selection
  │
  ▼
Asset Discovery
  │
  ▼
DNS Resolution
  │
  ▼
Live Host Discovery
  │
  ▼
Port & Service Enumeration
  │
  ▼
Web Crawling
  │
  ▼
Parameter Discovery
  │
  ▼
Vulnerability Scanning
  │
  ▼
Finding Normalization
  │
  ▼
Deduplication
  │
  ▼
AI Correlation & Analysis
  │
  ▼
Risk Prioritization
  │
  ▼
Remediation Guidance
  │
  ▼
Security Report

```

---

## 🎯 Project Goals

VulnPilot is being developed around a few core principles:

1. **Unified Security Assessment:** Bring multiple security testing workflows into a single platform.
2. **Automation:** Reduce repetitive manual work involved in running and processing security tools.
3. **Context-Aware Analysis:** Preserve relationships between assets, services, endpoints, vulnerabilities, and evidence.
4. **Intelligent Prioritization:** Use contextual information and AI-assisted analysis to help security engineers focus on the most meaningful findings.
5. **Reusable Security Data:** Store and reuse previously discovered assets and intermediate results instead of repeatedly scanning the same targets.

---

## 🗺️ Roadmap

* [x] SAST pipeline
* [x] SCA pipeline
* [x] DAST integration
* [x] Web reconnaissance
* [x] Configurable reconnaissance profiles
* [x] ReconPipeline orchestration
* [x] Intermediate result storage
* [x] Tool enable/disable configuration
* [x] Custom scanner flags
* [x] Duplicate asset avoidance
* [x] Android APK analysis
* [x] AI-assisted vulnerability analysis
* [ ] Advanced finding correlation
* [ ] Attack-path visualization
* [ ] Continuous attack-surface monitoring
* [ ] Enhanced dynamic Android analysis
* [ ] iOS automated analysis pipeline
* [ ] Advanced risk scoring
* [ ] Enterprise reporting
* [ ] CI/CD security integration
* [ ] Multi-tenant deployment

---

## 🔐 Responsible Use

VulnPilot integrates offensive security tooling capable of interacting with real systems.

Use it only against:

* Systems you own
* Applications you are authorized to test
* Infrastructure covered by an explicit security-testing agreement
* Dedicated laboratory environments
* CTF and security research environments

The project should not be used to scan or attack systems without authorization.

---

## 📌 Status

VulnPilot is an actively developed security engineering project.

The architecture and capabilities are continuously evolving as additional security scanners, analysis engines, AI workflows, and assessment capabilities are integrated.

---

## 👨‍💻 Author

**Lakshay Bhatnagar**

*Cybersecurity | Application Security | Offensive Security | Security Automation*

---

### ⭐ If you find VulnPilot interesting

Star the repository and follow the project as VulnPilot evolves into a unified platform for automated security assessment and AI-assisted vulnerability analysis.
