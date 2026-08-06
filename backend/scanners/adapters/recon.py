"""Safe, independently registered reconnaissance scanner adapters."""

from __future__ import annotations

from abc import abstractmethod
from pathlib import Path
from typing import Any

from backend.models.schemas import VulnerabilityItem
from backend.parsers.recon_parser import parse_recon_output
from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class ReconScannerAdapter(SubprocessScannerAdapter):
    """Common stdout-to-artifact execution for reconnaissance CLIs."""

    supported_scan_types = frozenset({"default"})
    output_extension = "jsonl"

    @abstractmethod
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: ...

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError(f"{self.name} is not installed or not available on PATH.")
        output_path = output_dir / f"{self.name}.{self.output_extension}"
        await self._run_command(job_id, self.command(executable, target, custom_args), output_dir, stdout_path=output_path)
        output_path.touch(exist_ok=True)
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]:
        content = raw_results if isinstance(raw_results, bytes) else str(raw_results).encode("utf-8")
        return parse_recon_output(self.name, content)

    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        return parsed_results


class SubfinderScannerAdapter(ReconScannerAdapter):
    name, executable_name = "subfinder", "subfinder"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-d", target, "-silent", *custom_args]


class AmassScannerAdapter(ReconScannerAdapter):
    name, executable_name = "amass", "amass"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "enum", "-passive", "-d", target, *custom_args]


class DNSxScannerAdapter(ReconScannerAdapter):
    name, executable_name = "dnsx", "dnsx"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-d", target, "-silent", *custom_args]


class HTTPXScannerAdapter(ReconScannerAdapter):
    name, executable_name = "httpx", "httpx"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-u", target, "-silent", "-json", *custom_args]


class NaabuScannerAdapter(ReconScannerAdapter):
    name, executable_name = "naabu", "naabu"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-host", target, "-json", *custom_args]


class KatanaScannerAdapter(ReconScannerAdapter):
    name, executable_name = "katana", "katana"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-u", target, "-silent", "-jsonl", *custom_args]


class HakrawlerScannerAdapter(ReconScannerAdapter):
    name, executable_name = "hakrawler", "hakrawler"
    output_extension = "txt"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-url", target, "-plain", *custom_args]


class ArjunScannerAdapter(ReconScannerAdapter):
    name, executable_name = "arjun", "arjun"
    def command(self, executable: str, target: str, custom_args: list[str]) -> list[str]: return [executable, "-u", target, "-oJ", "-", *custom_args]
