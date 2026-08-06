"""Nuclei execution adapter that always persists JSON output."""

from pathlib import Path
from typing import Any

from backend.models.schemas import VulnerabilityItem
from backend.parsers.nuclei_parser import parse_nuclei_json
from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class NucleiScannerAdapter(SubprocessScannerAdapter):
    name = "nuclei"
    executable_name = "nuclei"
    supported_scan_types = frozenset({"default", "web", "technology", "cve"})
    _TAGS = {"default": [], "web": ["-tags", "http"], "technology": ["-tags", "tech"], "cve": ["-tags", "cve"]}

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("Nuclei is not installed or not available on PATH.")
        if any(argument in {"-json", "-jsonl", "-o"} or argument.startswith("-o=") for argument in custom_args):
            raise ValueError("Nuclei output arguments are managed by VulnPilot.")
        output_path = output_dir / "nuclei.jsonl"
        command = [executable, "-u", target, "-jsonl", "-o", str(output_path), *self._TAGS[scan_type.lower()], *custom_args]
        await self._run_command(job_id, command, output_dir)
        output_path.touch(exist_ok=True)
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]:
        content = raw_results if isinstance(raw_results, bytes) else str(raw_results).encode("utf-8")
        return parse_nuclei_json(content)

    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        return parsed_results
