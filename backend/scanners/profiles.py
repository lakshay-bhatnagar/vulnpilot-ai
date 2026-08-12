"""Declarative advanced scan profiles; routes never hardcode scanner lists."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    label: str
    tools: dict[str, tuple[str, ...]]

    def resolve(self, mode: str) -> tuple[str, ...]:
        try:
            return self.tools[mode.lower()]
        except KeyError as exc:
            raise ValueError(f"Profile '{self.name}' does not support mode '{mode}'.") from exc


PROFILES = {
    "external_attack_surface": ScanProfile("external_attack_surface", "External Attack Surface", {
        "quick": ("subfinder", "dnsx", "httpx", "naabu", "nuclei"),
        "standard": ("subfinder", "amass", "dnsx", "httpx", "naabu", "nmap", "katana", "nuclei"),
        "comprehensive": ("subfinder", "amass", "dnsx", "httpx", "naabu", "nmap", "katana", "arjun", "nuclei"),
    }),
    "web_application_assessment": ScanProfile("web_application_assessment", "Web Application Assessment", {
        "quick": ("httpx", "nuclei"),
        "standard": ("httpx", "katana", "arjun", "nuclei"),
        "comprehensive": ("httpx", "katana", "hakrawler", "arjun", "nuclei"),
    }),
    "infrastructure_assessment": ScanProfile("infrastructure_assessment", "Infrastructure Assessment", {
        "quick": ("naabu", "nmap"),
        "standard": ("naabu", "nmap", "nuclei"),
        "comprehensive": ("naabu", "nmap", "nuclei"),
    }),
    "mobile_assessment": ScanProfile("mobile_assessment", "Mobile Assessment", {
        "quick": ("mobsf",),
        "standard": ("apktool", "jadx", "mobsf", "semgrep", "trivy", "syft", "osv-scanner"),
        "comprehensive": ("apktool", "jadx", "mobsf", "semgrep", "trivy", "syft", "osv-scanner"),
    }),
    "source_code_assessment": ScanProfile("source_code_assessment", "Source Code Assessment", {
        "quick": ("semgrep",), "standard": ("semgrep",), "comprehensive": ("semgrep",),
    }),
    "software_composition_analysis": ScanProfile("software_composition_analysis", "Software Composition Analysis", {
        "quick": ("syft", "osv-scanner"),
        "standard": ("syft", "trivy", "osv-scanner"),
        "comprehensive": ("syft", "trivy", "osv-scanner"),
    }),
    "custom_scan": ScanProfile("custom_scan", "Custom Scan", {
        "quick": (), "standard": (), "comprehensive": (),
    }),
}


def resolve_profile(name: str, mode: str) -> tuple[str, ...]:
    profile = PROFILES.get(name.lower())
    if profile is None:
        raise ValueError(f"Unknown scan profile '{name}'.")
    return profile.resolve(mode)
