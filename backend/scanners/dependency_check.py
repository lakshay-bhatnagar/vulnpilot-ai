"""OWASP Dependency-Check runtime scanner."""

from pathlib import Path

from backend.scanners.runtime_base import BaseScanner
from backend.scanners.runtime_parsers import parse_dependency_check_json


class DependencyCheckScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "dependency-check", "dependency-check", "owasp/dependency-check:latest", "dependency-check-report.json"

    def __init__(self) -> None:
        super().__init__(parse_dependency_check_json)

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Dependency-Check requires a project directory.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "--scan", target, "--format", "JSON", "--out", str(output_path.parent), *custom_args]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["--scan", target, "--format", "JSON", "--out", "/workspace/output", *custom_args]
