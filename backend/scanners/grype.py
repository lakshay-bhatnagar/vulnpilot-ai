"""Grype dependency vulnerability scanner."""

from pathlib import Path

from backend.scanners.runtime_base import BaseScanner
from backend.scanners.runtime_parsers import parse_grype_json


class GrypeScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "grype", "grype", "anchore/grype:latest", "grype.json"

    def __init__(self) -> None:
        super().__init__(parse_grype_json)

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Grype requires a project directory.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, f"dir:{target}", "-o", "json", "--file", str(output_path), *custom_args]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return [f"dir:{target}", "-o", "json", "--file", f"/workspace/output/{self.output_filename}", *custom_args]
