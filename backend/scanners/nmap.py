"""Runtime Nmap scanner; XML output is normalized through the established parser."""

from pathlib import Path

from backend.parsers.nmap_parser import parse_nmap_xml
from backend.scanners.runtime_base import BaseScanner


class NmapScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "nmap", "nmap", "instrumentisto/nmap:latest", "nmap.xml"
    supported_scan_types = frozenset({"default", "discovery", "tcp", "udp", "version", "os", "nse", "service", "ssl", "http"})
    _type_args = {"default": ["-sV", "--script", "default"], "discovery": ["-sn"], "tcp": ["-sT"], "udp": ["-sU"], "version": ["-sV"], "os": ["-O"], "nse": ["--script", "default"], "service": ["-sV"], "ssl": ["-sV", "--script", "ssl-enum-ciphers"], "http": ["-sV", "--script", "http-title,http-headers"]}

    def __init__(self) -> None:
        super().__init__(parse_nmap_xml)

    def _validate_args(self, values: list[str]) -> list[str]:
        if any(value in {"-oX", "-oA", "-oN", "-oG", "-oS"} or value.startswith(("-oX", "-oA", "-oN", "-oG", "-oS")) for value in values):
            raise ValueError("Nmap output arguments are managed by VulnPilot.")
        return values

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, *self._type_args[scan_type], *self._validate_args(custom_args), "-oX", str(output_path), target]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return [*self._type_args[scan_type], *self._validate_args(custom_args), "-oX", f"/workspace/output/{self.output_filename}", target]
