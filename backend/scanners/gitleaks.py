"""Gitleaks secret-detection scanner."""

from pathlib import Path

from backend.scanners.runtime_base import BaseScanner
from backend.scanners.runtime_parsers import parse_gitleaks_json


class GitleaksScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "gitleaks", "gitleaks", "zricethezav/gitleaks:latest", "gitleaks.json"

    def __init__(self) -> None:
        super().__init__(parse_gitleaks_json)

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Gitleaks requires a source directory.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "detect", "--source", target, "--report-format", "json", "--report-path", str(output_path), "--no-banner", *custom_args]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["detect", "--source", target, "--report-format", "json", "--report-path", f"/workspace/output/{self.output_filename}", "--no-banner", *custom_args]
