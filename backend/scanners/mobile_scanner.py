"""Mobile assessment execution plans built from existing scanner adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from backend.scanners.profiles import resolve_profile


@dataclass(frozen=True)
class MobileScanPlan:
    scanners: tuple[str, ...]
    targets: dict[str, str]


class MobileScanner:
    """Creates platform-specific plans without duplicating individual tool logic."""

    _IOS_SCANNERS = ("mobsf", "semgrep")

    def build_plan(self, package_type: str, package_path: Path, workspace: Path, mode: str) -> MobileScanPlan:
        if package_type == "apk":
            scanners = resolve_profile("mobile_assessment", mode)
            source_directory = workspace / "jadx-decompiled"
            return MobileScanPlan(
                scanners=scanners,
                targets={
                    "apktool": str(package_path),
                    "jadx": str(package_path),
                    "mobsf": str(package_path),
                    "semgrep": str(source_directory),
                    "trivy": str(source_directory),
                    "syft": str(source_directory),
                    "osv-scanner": str(source_directory),
                },
            )
        if package_type == "ipa":
            static_directory = workspace / "ipa-static"
            return MobileScanPlan(
                scanners=self._IOS_SCANNERS,
                targets={"mobsf": str(package_path), "semgrep": str(static_directory)},
            )
        raise ValueError(f"Unsupported mobile package type '{package_type}'.")

    @staticmethod
    def phase_for(scanner_name: str) -> str:
        phases = {
            "apktool": "Decompiling APK with APKTool",
            "jadx": "Decompiling APK with JADX",
            "mobsf": "Running MobSF",
            "semgrep": "Running Semgrep static analysis",
            "trivy": "Running Dependency Scan with Trivy",
            "syft": "Generating mobile dependency SBOM",
            "osv-scanner": "Running Dependency Scan with OSV Scanner",
        }
        return phases.get(scanner_name, f"Running {scanner_name}")


mobile_scanner = MobileScanner()
