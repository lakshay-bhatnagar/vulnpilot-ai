"""Runtime Trivy filesystem vulnerability scanner."""

from pathlib import Path

from backend.parsers.dependency_parser import parse_trivy_json
from backend.scanners.runtime_base import BaseScanner


class TrivyScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "trivy", "trivy", "aquasec/trivy:latest", "trivy.json"

    def __init__(self) -> None:
        super().__init__(parse_trivy_json)

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Trivy requires a project directory.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "fs", "--format", "json", "--output", str(output_path), *custom_args, target]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["fs", "--format", "json", "--output", f"/workspace/output/{self.output_filename}", *custom_args, target]
