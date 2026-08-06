"""Dependency scanning adapters. A future Grype adapter can share this contract."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from backend.models.schemas import VulnerabilityItem
from backend.parsers.dependency_parser import parse_osv_json, parse_trivy_json
from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class DependencyScannerAdapter(SubprocessScannerAdapter):
    supported_scan_types = frozenset({"default"})

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError(f"{self.name} requires an extracted project directory.")


class SyftScannerAdapter(DependencyScannerAdapter):
    name, executable_name = "syft", "syft"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("Syft is not installed or not available on PATH.")
        output_path = output_dir / "sbom.cdx.json"
        await self._run_command(job_id, [executable, f"dir:{target}", "-o", f"cyclonedx-json={output_path}"], output_dir)
        if not output_path.is_file():
            raise RuntimeError("Syft completed without producing an SBOM.")
        project_sbom = Path(target) / "sbom.cdx.json"
        shutil.copyfile(output_path, project_sbom)
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]: return []
    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]: return parsed_results


class TrivyScannerAdapter(DependencyScannerAdapter):
    name, executable_name = "trivy", "trivy"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("Trivy is not installed or not available on PATH.")
        output_path = output_dir / "trivy.json"
        await self._run_command(job_id, [executable, "fs", "--format", "json", "--output", str(output_path), target], output_dir)
        if not output_path.is_file():
            raise RuntimeError("Trivy completed without producing JSON output.")
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]: return parse_trivy_json(raw_results if isinstance(raw_results, bytes) else str(raw_results).encode())
    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]: return parsed_results


class OsvScannerAdapter(DependencyScannerAdapter):
    name, executable_name = "osv-scanner", "osv-scanner"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("OSV Scanner is not installed or not available on PATH.")
        output_path = output_dir / "osv.json"
        await self._run_command(job_id, [executable, "--recursive", "--format", "json", "--output", str(output_path), target], output_dir)
        if not output_path.is_file():
            raise RuntimeError("OSV Scanner completed without producing JSON output.")
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]: return parse_osv_json(raw_results if isinstance(raw_results, bytes) else str(raw_results).encode())
    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]: return parsed_results
