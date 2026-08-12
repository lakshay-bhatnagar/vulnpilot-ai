"""Runtime Semgrep SAST scanner."""

from pathlib import Path

from backend.parsers.semgrep_parser import parse_semgrep_json
from backend.scanners.runtime_base import BaseScanner


class SemgrepScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "semgrep", "semgrep", "semgrep/semgrep:latest", "semgrep.json"

    def __init__(self) -> None:
        super().__init__(parse_semgrep_json)

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Semgrep requires an extracted source directory.")

    def _validate_args(self, values: list[str]) -> list[str]:
        if any(value in {"--json", "--output", "-o"} or value.startswith("--output=") for value in values):
            raise ValueError("Semgrep output arguments are managed by VulnPilot.")
        return values

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "scan", "--config", "auto", "--json", "--output", str(output_path), *self._validate_args(custom_args), target]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["scan", "--config", "auto", "--json", "--output", f"/workspace/output/{self.output_filename}", *self._validate_args(custom_args), target]
