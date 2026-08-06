"""Semgrep SAST adapter; CodeQL can join this registry as another adapter later."""

from pathlib import Path
from typing import Any

from backend.models.schemas import VulnerabilityItem
from backend.parsers.semgrep_parser import parse_semgrep_json
from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class SemgrepScannerAdapter(SubprocessScannerAdapter):
    name = "semgrep"
    executable_name = "semgrep"
    supported_scan_types = frozenset({"default"})

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Semgrep requires an extracted source directory.")

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("Semgrep is not installed or not available on PATH.")
        if any(argument in {"--json", "--output", "-o"} or argument.startswith("--output=") for argument in custom_args):
            raise ValueError("Semgrep output arguments are managed by VulnPilot.")
        output_path = output_dir / "semgrep.json"
        command = [executable, "scan", "--config", "auto", "--json", "--output", str(output_path), *custom_args, target]
        await self._run_command(job_id, command, output_dir)
        if not output_path.is_file():
            raise RuntimeError("Semgrep completed without producing JSON output.")
        return ScanExecutionResult(raw_output_path=output_path)

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]:
        content = raw_results if isinstance(raw_results, bytes) else str(raw_results).encode("utf-8")
        return parse_semgrep_json(content)

    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        return parsed_results
