"""Runtime Nuclei scanner with JSONL output."""

from pathlib import Path

from backend.parsers.nuclei_parser import parse_nuclei_json
from backend.scanners.runtime_base import BaseScanner


class NucleiScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "nuclei", "nuclei", "projectdiscovery/nuclei:latest", "nuclei.jsonl"
    supported_scan_types = frozenset({"default", "web", "technology", "cve"})
    _tags = {"default": [], "web": ["-tags", "http"], "technology": ["-tags", "tech"], "cve": ["-tags", "cve"]}

    def __init__(self) -> None:
        super().__init__(parse_nuclei_json)

    def _validate_args(self, values: list[str]) -> list[str]:
        if any(value in {"-json", "-jsonl", "-o"} or value.startswith("-o=") for value in values):
            raise ValueError("Nuclei output arguments are managed by VulnPilot.")
        return values

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "-u", target, "-jsonl", "-o", str(output_path), *self._tags[scan_type], *self._validate_args(custom_args)]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["-u", target, "-jsonl", "-o", f"/workspace/output/{self.output_filename}", *self._tags[scan_type], *self._validate_args(custom_args)]
