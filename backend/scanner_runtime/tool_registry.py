"""Scanner registration and runtime availability discovery."""

from __future__ import annotations

from backend.scanners.apktool import ApktoolScanner
from backend.scanners.dependency_check import DependencyCheckScanner
from backend.scanners.gitleaks import GitleaksScanner
from backend.scanners.grype import GrypeScanner
from backend.scanners.jadx import JadxScanner
from backend.scanners.mobsf import MobSFScanner
from backend.scanners.nmap import NmapScanner
from backend.scanners.nuclei import NucleiScanner
from backend.scanners.runtime_base import BaseScanner
from backend.scanners.semgrep import SemgrepScanner
from backend.scanners.syft import SyftScanner
from backend.scanners.trivy import TrivyScanner


class ToolRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        key = scanner.name.lower()
        if key in self._scanners:
            raise ValueError(f"Scanner '{scanner.name}' is already registered.")
        self._scanners[key] = scanner

    def get(self, scanner_name: str) -> BaseScanner:
        scanner = self._scanners.get(scanner_name.lower())
        if scanner is None:
            raise ValueError(f"Unknown scanner '{scanner_name}'. Available: {', '.join(sorted(self._scanners))}.")
        return scanner

    def all(self) -> list[BaseScanner]:
        return list(self._scanners.values())

    async def health(self) -> list[dict[str, object]]:
        return [await scanner.health_check() for scanner in self.all()]


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for scanner in (NmapScanner(), NucleiScanner(), SemgrepScanner(), TrivyScanner(), DependencyCheckScanner(), GrypeScanner(), SyftScanner(), GitleaksScanner(), MobSFScanner(), JadxScanner(), ApktoolScanner()):
        registry.register(scanner)
    return registry
