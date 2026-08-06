"""Nmap execution adapter that always persists XML output."""

from pathlib import Path
from typing import Any

from backend.models.schemas import VulnerabilityItem
from backend.parsers.nmap_parser import parse_nmap_xml
from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class NmapScannerAdapter(SubprocessScannerAdapter):
    name = "nmap"
    executable_name = "nmap"
    supported_scan_types = frozenset({"default", "discovery", "tcp", "udp", "version", "os", "nse", "service", "ssl", "http"})

    _TYPE_ARGS = {
        "default": ["-sV", "--script", "default"],
        "discovery": ["-sn"],
        "tcp": ["-sT"],
        "udp": ["-sU"],
        "version": ["-sV"],
        "os": ["-O"],
        "nse": ["--script", "default"],
        "service": ["-sV"],
        "ssl": ["-sV", "--script", "ssl-enum-ciphers"],
        "http": ["-sV", "--script", "http-title,http-headers"],
    }
    _FORBIDDEN_OUTPUT_ARGS = {"-oX", "-oA", "-oN", "-oG", "-oS", "--stylesheet", "--webxml"}

    def _validated_custom_args(self, custom_args: list[str]) -> list[str]:
        if any(
            argument in self._FORBIDDEN_OUTPUT_ARGS
            or argument.startswith(("-oX", "-oA", "-oN", "-oG", "-oS", "--stylesheet="))
            for argument in custom_args
        ):
            raise ValueError("Nmap output arguments are managed by VulnPilot; use custom arguments only for scan behavior.")
        return custom_args

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("Nmap is not installed or not available on PATH.")
        output_path = output_dir / "nmap.xml"
        command = [executable, *self._TYPE_ARGS[scan_type.lower()], *self._validated_custom_args(custom_args), "-oX", str(output_path), target]
        await self._run_command(job_id, command, output_dir)
        if not output_path.exists():
            raise RuntimeError("Nmap completed without producing XML output.")
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]:
        content = raw_results if isinstance(raw_results, bytes) else str(raw_results).encode("utf-8")
        return parse_nmap_xml(content)

    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        return parsed_results
